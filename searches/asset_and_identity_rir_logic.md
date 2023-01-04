# Integrate Asset & Identity Information into Risk Incident Rules
This was a comment on this excellent [Splunk Idea](https://ideas.splunk.com/ideas/ESSID-I-253) to lower() or upper() the risk_object in Risk Incident Rules, which goes one step further by integrating A&I information:

```
| tstats `summariesonly` min(_time) as firstTime max(_time) as lastTime sum(All_Risk.calculated_risk_score) as risk_score, count(All_Risk.calculated_risk_score) as risk_event_count,values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id, values(All_Risk.annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id, values(All_Risk.tag) as tag, values(source) as source from datamodel=Risk.All_Risk by All_Risk.risk_object,All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| eval risk_object=upper(risk_object)
| lookup update=true identity_lookup_expanded identity as risk_object OUTPUTNEW _key as asset_identity_id,identity as asset_identity_value
| lookup update=true asset_lookup_by_str asset as risk_object OUTPUTNEW _key as asset_identity_id,asset as asset_identity_value
| eval asset_identity_risk_object=CASE(isnull(asset_identity_id),risk_object,true(),asset_identity_id)
| stats min(firstTime) as firstTime max(lastTime) as lastTime sum(risk_score) as risk_score, sum(risk_event_count) as risk_event_count,values(annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id, dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count, values(annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id, dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count, values(tag) as tag, values(source) as source, dc(source) as source_count values(asset_identity_value) as asset_identity_value values(risk_object) as risk_object dc(risk_object) as risk_object_count by asset_identity_risk_object,risk_object_type
| eval "annotations.mitre_attack"='annotations.mitre_attack.mitre_technique_id', risk_threshold=100
| eval user=case(risk_object_type="user",risk_object,true(),user),src=case(risk_object_type="system",risk_object,true(),src)
| where risk_score >= $risk_threshold$
| `get_risk_severity(risk_score)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```
As they mention in the comment -- the one "catch" is you'll need to change your throttle object from "risk_object" to "asset_identity_risk_object" -- but this is great for preventing duplicate notables on the same basic user / system combination.

## Extra Credit
Adding the above logic will increase the accuracy of Risk based alerting, however pivoting via the built in drilldown will still be limited. The following changes will allow analysts to pivot directly to all Risk alerts detected by the assoicated RIR.

Create a macro called "get_risk_asset_ident(2)".

![image](https://user-images.githubusercontent.com/38897662/207168499-31769136-2f36-4fe2-88a1-406f33558d40.png)

Give the macro the following SPL:
```
eval risk_in="$risk_object_in$",risk_type_in="$risk_object_type_in$"
| lookup update=true identity_lookup_expanded identity as risk_object OUTPUTNEW _key as assetid_ident_id,identity as assetid_ident_value 
| lookup update=true asset_lookup_by_str asset as risk_object OUTPUTNEW _key as assetid_asset_id,asset as assetid_asset_value 
| lookup update=true identity_lookup_expanded identity as risk_in OUTPUTNEW _key as assetid_in_ident,identity as assetid_in_ident_value 
| lookup update=true asset_lookup_by_str asset as risk_in OUTPUTNEW _key as assetid_in_asset,asset as assetid_in_asset_value 
| eval risk_object_out=CASE((risk_type_in="user" AND assetid_ident_id = 'assetid_in_ident'),assetid_in_ident_value, (risk_type_in="system" AND (assetid_asset_id = 'assetid_in_asset')),assetid_in_asset_value)
| eval risk_in=upper(risk_in)
| eval risk_object=upper(risk_object)
| where isnotnull(risk_object_out) OR (risk_object = risk_in)
```
Assign the following arguements:
```
risk_object_in,risk_object_type_in
```

Afterward the macro should have global perms allowing all users to read it. Then you may modify existing RIR drilldowns to include the macro similar to below:
```
| from datamodel:"Risk.All_Risk"  
| `get_risk_asset_ident($risk_object|s$,$risk_object_type|s$)`
| `get_correlations`  
| rename annotations.mitre_attack.mitre_tactic_id as mitre_tactic_id, annotations.mitre_attack.mitre_tactic as mitre_tactic, annotations.mitre_attack.mitre_technique_id as mitre_technique_id, annotations.mitre_attack.mitre_technique as mitre_technique
```
