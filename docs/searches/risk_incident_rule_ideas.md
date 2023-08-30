# Risk Incident Rule Ideas

Here are some alternative ways to alert from the risk index that you may find useful. Later searches will be relying on the base search found in the "Capped Risk Score by Source" approach.

- | Description
- | ---------- 
[Capped Risk Score by Source](#capped-risk-score-by-source) | From the [limit score stacking] approach(https://github.com/splunk/rba/blob/main/docs/searches/limit_score_stacking.md)
[Events from Multiple Sourcetypes](#events-from-multiple-sourcetypes) | For events from multiple sourcetypes
[Events from Multiple Sourcetypes with Meta-Scoring](#events-from-multiple-sourcetypes-with-meta-scoring) | Similar, but with more control over what alerts and how
[MITRE Counts with Meta-Scoring](#mitre-counts-with-meta-scoring) | Meta-scoring approach to MITRE alert
  
## Capped Risk Score by Source

Utilizes the [limit score stacking](https://github.com/splunk/rba/blob/main/docs/searches/limit_score_stacking.md) approach to limit score contribution from a single source to double of its highest scoring risk event.

```shell linenums="1"
| tstats `summariesonly`
count as count
sum(All_Risk.calculated_risk_score) as risk_score,
count(All_Risk.calculated_risk_score) as risk_event_count,
sum(All_Risk.calculated_risk_score) as summed_risk_score,
max(All_Risk.calculated_risk_score) as single_risk_score,
values(All_Risk.risk_message) as risk_message,
values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id,
dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count,
values(All_Risk.annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id,
dc(All_Risk.annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count,
values(All_Risk.tag) as tag,
values(All_Risk.threat_object) as threat_object,
values(All_Risk.threat_object_type) as threat_object_type,
dc(source) as source_count,
,max(_time) as _time
from datamodel=Risk.All_Risk by All_Risk.risk_object,All_Risk.risk_object_type, source | `drop_dm_object_name("All_Risk")` | eval "annotations.mitre_attack"='annotations.mitre_attack.mitre_technique_id' | `get_risk_severity(risk_score)`
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count
 BY risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where capped_risk_score > 100
```
  
## Events from Multiple Sourcetypes

This is a very effective approach that looks for when a single risk object has events from multiple security data sources. With a well-defined naming scheme for your searches, you may not need to utilize a saved search to retain this information in your risk rules. If you do, you could run something like this somewhat infrequently as a saved search:

```shell linenums="1"
| rest splunk_server=local count=0 /services/saved/searches
| search action.correlationsearch.enabled=1
| rename dispatch.earliest_time as early_time qualifiedSearch as search_spl
| table title search_spl
| eval data_sourcetype = case(
match(search_spl,".*\`(sysmon|wmi|powershell|wineventlog_(security|system))\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Endpoint.*") OR match(title,"Endpoint.*") OR match(search_spl,".*sourcetype\=(|\")(xmlwineventlog:microsoft-windows-sysmon/operational).*"),"Endpoint",
match(search_spl,".*datamodel(:|=|\s)(|\")Endpoint.*") OR match(title,"Threat.*") OR match(search_spl,".*sourcetype\=(|\")(wdtap:alerts).*"),"Malware",
match(search_spl,".*\`(okta|gws_reports_login)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Authentication.*"),"Authentication",
match(search_spl,".*datamodel(:|=|\s)(|\")Change.*"),"Change",
match(search_spl,".*\`(stream_http)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Web.*"),"Web",
match(search_spl,".*\`(o365_management_activity|gsuite_gmail)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Email.*"),"Email",
match(search_spl,".*\`(gsuite_gdrive)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Data Loss.*"),"DLP",
match(search_spl,".*datamodel(:|=|\s)(|\")Alerts.*"),"Alerts",
match(search_spl,".*datamodel(:|=|\s)(|\")Intrusion.*"),"IDS",
match(search_spl,".*\`(cisco_networks)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Network.*"),"Network",
match(search_spl,".*\`(kubernetes_azure|azuread|cloudtrail|aws_securityhub_finding|aws_cloudwatchlogs_eks|azure_audit|google_gcp_pubsub_message|aws_s3_accesslogs)\`.*"),"Cloud",
true(),"Unknown")
| fields - search_spl
| outputlookup RR_sources.csv
```

Which looks at the SPL of a search to determine which sourcetype to group it under. Please modify this search as you see fit for your environment. This allows you to create a Risk Incident Rule like this:

```shell linenums="1"
...
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| lookup RR_sources.csv title AS source OUTPUTNEW data_sourcetype
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count values(data_sourcetype) as sourcetypes dc(data_sourcetype) as sourcetype_count
 BY risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where sourcetype_count > 1
```

## Events from Multiple Sourcetypes with Meta-Scoring

Sometimes, you may need more ways of distinguishing which events should have more relevance in an alert beyond a simple count or distinct count. The gist of this strategy is to declare a new variable with a value of 0, then utilize multiple `eval` statements to add to this value based on attributes about the event. Remember that a `case()` statement will only apply **once** and will apply the first match it finds, so you want to ensure your most important matches hit first. Don't be afraid to stack multiple `eval` statements, and you'll have to tweak what the threshold is depending on the values you chose.

```shell linenums="1"
...
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| lookup RR_sources.csv title AS source OUTPUTNEW data_sourcetype
| rex field=risk_message "Severity\=(?<severity>\w*)\s"
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count values(data_sourcetype) as sourcetypes dc(data_sourcetype) as sourcetype_count
 BY risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| eval sourcetype_mod = 0
| eval sourcetype_mod = if(match(sourcetypes,"Endpoint"),sourcetype_mod+20,sourcetype_mod)
| eval sourcetype_mod = if(match(sourcetypes,"Malware"),sourcetype_mod+20,sourcetype_mod)
| eval sourcetype_mod = if(match(sourcetypes,"Web"),sourcetype_mod+10,sourcetype_mod)
| eval sourcetype_mod = if(match(sourcetypes,"DLP"),sourcetype_mod+10,sourcetype_mod)
| eval sourcetype_mod = case(
match(sourcetypes,"IDS") AND match(severity,"(high|critical)"),sourcetype_mod+20,
match(sourcetypes,"IDS"),sourcetype_mod+10,
true(),sourcetype_mod)
| where sourcetype_mod > 39
```

Because `sourcetypes` is now a multi-valued field by risk_object, I had to create multiple `eval` checks so that the operation would apply more than once if events from multiple sourcetypes were found. You can also see how I pulled out severity from the risk_message earlier on with `rex` so I could make a distinction between higher and lower severity IDS events in the meta-scoring. This assumes only my IDS events have that particular formatting to indicate severity; you may have to use more logic to distinguish different sourcetypes and severities, it's just an example. 

For the scoring threshold of 40, I chose this because of how I've structured the score additions. I will get an alert if a risk object has events from:

- 2 of (Endpoint / Malware / IDS High-Critical)
- 1 of (Endpoint / Malware) + 2 of (Web / DLP / IDS Low-Medium)

Which may remove a lot of noise from combinations which aren't as likely to be malicious. It is still worthwhile to occasionally review what doesn't pass the threshold to ensure you've crafted a method that surfaces high-fidelity alerts, or are caught with other Risk Incident Rules.

## MITRE Counts with Meta-Scoring

The meta-scoring method is useful for getting more value from your MITRE count thresholding rules. 

```shell linenums="1"
...
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| eval mitre_weight = case(
capped_risk_score>70,"0",
capped_risk_score>40,"0.5",
capped_risk_score>5,"0.75",
true(),"1")
| eval mitre_weight_tactic = mitre_weight * mitre_tactic_id_count
| eval mitre_weight_technique = mitre_weight * mitre_technique_id_count
| eventstats sum(mitre_weight_tactic) as mitre_weight_tactic_total sum(mitre_weight_technique) as mitre_weight_technique_total by risk_object risk_object_type source
| eval mitre_tactic_id_count = mitre_tactic_id_count - mitre_weight_tactic_total
| eval mitre_technique_id_count = mitre_technique_id_count - mitre_weight_technique_total
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score sum(mitre_tactic_id_count) as mitre_tactic_id_count sum(mitre_technique_id_count) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count
 BY risk_object risk_object_type
| fields - mitre_weight* single_risk_score count
| eval risk_score = summed_risk_score
| eval mitre_mod = 0
| eval mitre_mod = case(
mitre_tactic_id_count > 3,mitre_mod+20,
mitre_tactic_id_count < 4 AND mitre_tactic_id_count > 1,mitre_mod+10,
true(),mitre_mod)
| eval mitre_mod = case(
mitre_technique_id_count > 4,mitre_mod+20,
mitre_technique_id_count < 5 AND mitre_technique_id_count > 2,mitre_mod+10,
true(),mitre_mod)
| eval mitre_mod = case(
mvcount(source) > 4,mitre_mod+20,
mvcount(source) < 5 AND mvcount(source) > 1,mitre_mod+10,
true(),mitre_mod)
| eval mitre_mod = case(
match(sourcetypes,"(Malware|Endpoint)"),mitre_mod+20,
match(sourcetypes,"IDS"),mitre_mod+10,
true(),mitre_mod)
| eval mitre_mod = case(
match(user_category,"(privileged|technical|executive|watchlist)"),mitre_mod+20,
match(src_category,"(Server|DMZ)"),mitre_mod+10,
true(),mitre_mod)
| where mitre_mod > 49
```

Near the beginning, we juggle some logic for counting events differently which have a lower risk score because when we aggregate on the count of MITRE Tactics/Techniques involved, we might want to treat events with a higher risk score as counting more heavily toward the overall total. This is especially true when aggregating events over longer periods like the out of the box 7 day rule, or something going as far back as 30 or 90 days.

Now in the meta-scoring, we have all sorts of ways to distinguish what might be more relevant to us. Now we incorporate:

- Number of risk-score-weight-adjusted MITRE tactics
- Number of risk-score-weight-adjusted MITRE techniques
- Number of distinct rules firing
- Rules from particular sourcetypes adding more weight
- Specific user or system categories adding more weight

Which gives us more control over the types of events that might bubble up in our alerts.
