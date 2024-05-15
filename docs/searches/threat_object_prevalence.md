# Threat Object Prevalence

THIS IS A WIP PAGE, THIS IS COMING SOON!

<!-- TODO:
One of my favorite features in RBA is knowing how often something has occurred in an environment; generally, the more rare or anomalous something is, the more likely it is to be malicious. The threat object drilldown in the sample [Risk Investigation Dashboard](https://splunk.github.io/rba/dashboards/risk_investigation/){ target="blank" } is designed to offer an analyst that context, but with a simple saved search, we could use that context in our Risk Notables as well.

## Create a Saved Search

You'll have to decide how often you want this information updated, but utilizing `tstats` against the Risk Index means this should be pretty snappy and could run pretty frequently over a long timeframe. Create a new saved search with this logic:

```shell linenums="1"
| tstats summariesonly=t count dc(All_risk.risk_object) as dc_objects earliest(_time) as first_time latest(_time) as last_time from datamodel=Risk.All_Risk by All_Risk.threat_object
| rename All_Risk.threat_object as threat_object
| convert ctime(first_time) as first_time | convert ctime(last_time) as last_time
| outputlookup threat_object_count.csv
```

!!! note "You might want to include more details here, like lists of searches that fired this threat object and so on."

## Incorporating into Risk Notables

I will use the base logic for the [limit score stacking](https://github.com/splunk/rba/blob/main/docs/searches/limit_score_stacking.md){ target="blank" } Risk Incident Rule with some modifications, and use the datamodel command for clarity and speed:

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
values(All_Risk.threat_object_type) as threat_object_type,
dc(source) as source_count,
,max(_time) as _time
from datamodel=Risk.All_Risk by All_Risk.risk_object,All_Risk.risk_object_type, source, All_Risk.threat_object | `drop_dm_object_name("All_Risk")` | eval "annotations.mitre_attack"='annotations.mitre_attack.mitre_technique_id' | `get_risk_severity(risk_score)`
| eval capped_risk_score=if(summed_risk_score < single_risk_score*2, summed_risk_score, single_risk_score*2)
| stats values(*) as * sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count sum(risk_event_count) as risk_event_count dc(source) as source_count
 BY risk_object risk_object_type
| fields - single_risk_score count
| eval risk_score = summed_risk_score
| where capped_risk_score > 100
```

We have to keep in mind order of operations to ensure our logic continues working as intended. I took out the `values()` piece for threat_object, and add it to the `BY` clause so we keep things separate while we enrich with our lookup. Then I utilize that information to adjust the risk score of events which happen a lot, especially when observed on multiple machines. Finally I wrapped it back up with `stats` to utilize our score stacking logic again, now informed by our threat object prevalence adjustments.


potentially an image here to show the adjusted scores after threat object changed them? -->
