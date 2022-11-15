# Integrate Asset & Identity Information into Risk Incident Rules
This was a comment on this excellent [Splunk Idea](https://ideas.splunk.com/ideas/ESSID-I-253) to lower() or upper() the risk_object in Risk Incident Rules, which goes one step further by integrating A&I information:

```
| tstats `summariesonly` min(_time) as firstTime max(_time) as lastTime sum(All_Risk.calculated_risk_score) as risk_score, count(All_Risk.calculated_risk_score) as risk_event_count,values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id, values(All_Risk.annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id, values(All_Risk.tag) as tag, values(source) as source from datamodel=Risk.All_Risk by All_Risk.risk_object,All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| eval risk_object=upper(risk_object)
| lookup update=true identity_lookup_expanded identity as risk_object OUTPUTNEW _key as asset_identity_id,identity as asset_identity_value
| lookup update=true asset_lookup_by_str asset as risk_object OUTPUTNEW _key as asset_identity_id,asset as asset_identity_value
| eval asset_identity_risk_object=CASE(isnull(asset_identity_id),risk_object,true(),asset_identity_id)
| stats min(firstTime) as firstTime max(lastTime) as lastTime sum(risk_score) as risk_score, sum(risk_event_count) as risk_event_count,values(annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id, dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count, values(annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id, dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count, values(tag) as tag, values(source) as source, sum(source) as source_count values(asset_identity_value) as asset_identity_value values(risk_object) as risk_object dc(risk_object) as risk_object_count by asset_identity_risk_object,risk_object_type
| eval "annotations.mitre_attack"='annotations.mitre_attack.mitre_technique_id', risk_threshold=100
| eval user=case(risk_object_type="user",risk_object,true(),user),src=case(risk_object_type="system",risk_object,true(),src)
| where risk_score >= $risk_threshold$
| `get_risk_severity(risk_score)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```
As they mention in the comment -- the one "catch" is you'll need to change your throttle object from "risk_object" to "asset_identity_risk_object" -- but this is great for preventing duplicate notables on the same basic user / system combination.
