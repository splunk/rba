# Risk Incident Rule Ideas

Here are some alternative ways to alert from the risk index that you may find useful. Later searches will be relying on the base search found in the "Capped Risk Score by Source" approach.

Name | Description
---- | ---------- 
[Capped Risk Score by Source](#capped-risk-score-by-source) | From the [limit score stacking](./limit_score_stacking.md) approach
[Events from Multiple Sourcetypes](#events-from-multiple-sourcetypes) | For events from multiple sourcetypes
[Events from Multiple Sourcetypes with Meta-Scoring](#events-from-multiple-sourcetypes-with-meta-scoring) | Similar, but with more control over what alerts and how
[MITRE Counts with Meta-Scoring](#mitre-counts-with-meta-scoring) | Meta-scoring approach to MITRE alert
  
## Capped Risk Score by Source

Utilizes the [limit score stacking](./limit_score_stacking.md) approach to limit score contribution from a single source to double of its highest scoring risk event.

```shell linenums="1"
| tstats `summariesonly`
count as count
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
from datamodel=Risk.All_Risk by All_Risk.normalized_risk_object,All_Risk.risk_object_type, source | `drop_dm_object_name("All_Risk")` | eval "annotations.mitre_attack"='annotations.mitre_attack.mitre_technique_id' | `get_risk_severity(risk_score)`
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count
 BY normalized_risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where capped_risk_score > 100
```
  
## Events from Multiple Sourcetypes

This is a very effective approach that looks for when a single risk object has events from multiple security data sources. With a well-defined naming scheme for your searches (or bringing forward index+sourcetype in all of your risk rules), you may not need to utilize a saved search to retain this information in your risk rules. Otherwise, you could run something like this somewhat infrequently as a saved search:

```shell linenums="1"
| rest splunk_server=local count=0 /services/saved/searches f=title f=qualifiedSearch search="action.correlationsearch.detection_type=ebd"
| rename qualifiedSearch as search_spl
| table title search_spl
| eval data_sourcetype = case(
match(search_spl,".*All_Risk.*"),"Risk",
match(search_spl,".*\`(wineventlog_.*|certificateservices_lifecycle|windows_exchange_iis|iis_.*|ntlm_audit|printservice|linux_auditd|ms365_defender_incident_alerts|ms_defender_atp_alerts|osquery_.*|crowdstrike_stream|capi2_operational|subjectinterfacepackage|linux_hosts|remoteconnectionmanager|crowdstrike_identities|applocker|ms_defender|sysmon|wmi|powershell|wineventlog_(security|system))\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Endpoint.*") OR match(title,"Endpoint.*") OR match(search_spl,".*sourcetype\=(|\")(xmlwineventlog:microsoft-windows-sysmon/operational).*"),"Endpoint",
match(search_spl,".*datamodel(:|=|\s)(|\")Endpoint.*") OR match(title,"Threat.*") OR match(search_spl,".*sourcetype\=(|\")(wdtap:alerts).*"),"Malware",
match(search_spl,".*\`(o365_graph|okta|pingid|admon|gws_reports_login|cisco_duo_(administrator|activity))\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Authentication.*"),"Authentication",
match(search_spl,".*datamodel(:|=|\s)(|\")Change.*"),"Change",
match(search_spl,".*\`(stream_http|zscaler_proxy|stream_dns)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Web.*"),"Web",
match(search_spl,".*\`(o365_management_activity|gsuite_gmail|gsuite_calendar|msexchange_management)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Email.*"),"Email",
match(search_spl,".*\`(gsuite_gdrive|gsuite_drive)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Data Loss.*"),"DLP",
match(search_spl,".*(moveit_sftp_logs|crushftp|cisco_ai_defense|nginx_access_logs|zoom_index|papercutng|appdynamics_security|ivanti_vtm_audit).*"),"Application",
match(search_spl,".*datamodel(:|=|\s)(|\")Alerts.*"),"Alerts",
match(search_spl,".*datamodel(:|=|\s)(|\")Intrusion.*") OR match(search_spl,".*(suricata|zeek_.*).*"),"IDS",
match(search_spl,".*\`(f5_bigip_rogue|cisco_networks|cisco_asa|cisco_network_visibility_module_flowdata|cisco_secure_firewall)\`.*") OR match(search_spl,".*datamodel(:|=|\s)(|\")Network.*"),"Network",
match(search_spl,".*circleci.*|github_enterprise|github_organizations"),"Development",
match(search_spl,".*(kube_container_falco|kube_objects_events|esxi_syslog|cisco_isovalent|kube_audit|kubernetes_metrics|kubernetes_azure|kubernetes_container_controller).*"),"Orchestration",
match(search_spl,".*\`(gws_reports_admin|azuread|cloudtrail|cloudwatchlogs_vpcflow|aws_securityhub_finding|aws_cloudwatchlogs_eks|azure_audit|google_gcp_pubsub_message|aws_s3_accesslogs|amazon_security_lake|azure_monitor_aad|azure_monitor_activity)\`.*"),"Cloud",
match(search_spl,".*(m365_copilot_graph_api|m365_exported_ediscovery_prompt_logs|ollama_server).*"),"AI",
match(search_spl,".*(splunkd|driverinventory|bootloader_inventory|splunk_pdfgen|lookup-table-files|get_integer_seq|eval punycode|no_windows_updates).*"),"Audit",
true(),"Unknown")
| fields - search_spl
| outputlookup RR_sources.csv
```

Which looks at the SPL of a search to determine which sourcetype to group it under. Please modify this search as you see fit for your environment. This allows you to create a Risk Incident Rule like:

- Entity with Risk from Multiple Sourcetypes - 24h

```shell linenums="1"
...
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| lookup RR_sources.csv title AS source OUTPUTNEW data_sourcetype
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count values(data_sourcetype) as sourcetypes dc(data_sourcetype) as sourcetype_count
 BY risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where sourcetype_count > 2
```

- Entity with Multiple Detections within Single Sourcetype - 24h

```shell linenums="1"
...
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| lookup RR_sources.csv title AS source OUTPUTNEW data_sourcetype
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count 
 BY risk_object risk_object_type data_sourcetype
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where source_count > 2
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

For the scoring threshold of 40, I chose this because of how I've structured the score additions. I will get an alert if a risk object has events from:

- 2 of (Endpoint / Malware / IDS High-Critical)
- 1 of (Endpoint / Malware) + 2 of (Web / DLP / IDS Low-Medium)

Which may remove a lot of noise from combinations which aren't as likely to be malicious. It is still worthwhile to occasionally review what doesn't pass the threshold to ensure you've crafted a method that surfaces high-fidelity alerts, or are caught with other Risk Incident Rules.

!!! note
    Because `sourcetypes` is now a multi-valued field by risk_object, I had to create multiple `eval` checks so that the operation would apply more than once if events from multiple sourcetypes were found. You can also see how I pulled out severity from the risk_message earlier on with `rex` so I could make a distinction between higher and lower severity IDS events in the meta-scoring. This assumes only my IDS events have that particular formatting to indicate severity; you may have to use more logic to distinguish different sourcetypes and severities, it's just an example. 

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

---

<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors/" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
