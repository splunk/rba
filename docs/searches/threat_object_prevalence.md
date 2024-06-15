# Threat Object Prevalence

One of my favorite features in RBA is knowing how often something has occurred in an environment; generally, the more rare or anomalous something is, the more likely it is to be malicious. The threat object drilldown in the sample [Risk Investigation Dashboard](https://splunk.github.io/rba/dashboards/risk_investigation/){ target="blank" } is designed to offer an analyst that context, but we could utilize unique counts of threat objects to automatically tune scores.

## Create a Saved Search

You'll have to decide how often you want this information updated, but utilizing `tstats` against the Risk Index means this should be pretty snappy and could run pretty frequently over a long timeframe. Create a new saved search with this logic, firing with a frequency you like, and looking back at least 7 days:

```shell linenums="1"
| from datamodel Risk.All_Risk
| eval threat_object = mvzip(threat_object_type,threat_object,"|||")
| table risk_object threat_object user dest source
| eval to_full = threat_object 
| eval to_split = mvjoin(to_full,"::::")
| eventstats count by threat_object
| sistats count values(to_full) values(user) values(dest) by threat_object,to_split,source
| rename psrsvd_vm_to_full AS to_full
| rename psrsvd_vm_user AS users
| rename psrsvd_vm_dest AS dests
| rename psrsvd_gc AS count
| rex field=to_full max_match=0 "(?<threat_pal_temp>.*?;\d+;)"
| rex field=users max_match=0 "(?<user_temp>.*?;\d+;)"
| rex field=dests max_match=0 "(?<dest_temp>.*?;\d+;)"
| eventstats count as count2 by threat_object
| table count user_temp dest_temp source threat_pal_temp threat_object count2
| stats max(count) as total_count dc(user_temp) as dc_users values(user_temp) as users dc(dest_temp) as dc_dests values(dest_temp) as dests dc(sources_temp) as dc_sources values(count2) as to_count by threat_object threat_pal_temp source
| table total_count to_count source dc_users users dc_dests dests threat_pal_temp threat_object
| rex field=threat_pal_temp "(?<threat_pal>.*?);(?<threat_count>\d+);"
| rex field=users "(?<users_temp>.*?);\d+;"
| rex field=dests "(?<dests_temp>.*?);\d+;"
| rex field=threat_object "^(?<threat_object_type>.+)\|\|\|(?<threat_notype>.*)"
| rex field=threat_object "^(?<threat_pal_type>.+)\|\|\|(?<threat_pal_notype>.*)"
| eval to_count = if(threat_pal=threat_object,to_count,total_count)
| stats sum(threat_count) as threat_count dc(users_temp) as dc_users dc(dests_temp) as dc_dests values(users) as users values(dests) as dests values(source) as sources dc(source) as dc_sources values(to_count) as to_count values(threat_object_type) as threat_object_type values(threat_notype) as threat_notype values(threat_pal_type) as threat_pal_type values(threat_pal_notype) as threat_pal_notype BY threat_object,threat_pal
| eval triage_status = case(
dc_dests>10,"many_dest",
dc_users>10,"many_user",
dc_dests>3,"multiple_dest",
dc_users>3,"multiple_user",
threat_count>10, "regular_event",
true(), "rare" )
| eval threat_multiplier = case(
triage_status="many_dest" OR triage_status="many_user","0",
triage_status="multiple_dest" OR triage_status="multiple_user","0.25",
triage_status="regular_event","0.5",
true(),"1")
| eval threat_info=triage_status." ".threat_object_type.": dc_users=".dc_users." dc_dests=".dc_dests." dc_sources=".dc_sources." observed_count/alt_count=".threat_count."/".to_count." threat_object=".threat_notype
| eval users = if(mvcount(users)>9,"10+ entities",users), dests = if(mvcount(dests)>9,"10+ entities",dests)
| table threat_multiplier threat_count to_count threat_info triage_status dc_users users dc_dests dests dc_sources sources threat_object threat_pal threat_object_type threat_pal_type threat_notype threat_pal_notype
| sort - threat_count
| outputlookup threat_check.csv
```

!!! note "What I've tried to do with this lookup is see how often each threat object fires with another pair, which adds some complexity to the logic but ensures that a unique threat object pairing maintains its score and doesn't decrease scores inadvertently when a regularly firing threat object fires with something new."

!!! note "The reason I sort in descending order by count is so that in the following search, mvindex() utilizes the highest count for that threat pairing."

!!! note "Feel free to tweak the threat_multiplier to your heart's content, or include additional logic with triage_status."

## Incorporating into Risk Notables

I will use the general logic for the [limit score stacking](https://github.com/splunk/rba/blob/main/docs/searches/limit_score_stacking.md){ target="blank" } Risk Incident Rule with some modifications, and the datamodel command for clarity and speed:

```shell linenums="1"
| datamodel Risk search
| `drop_dm_object_name("All_Risk")`
| eval threat_object = mvzip(threat_object_type,threat_object,"|||")
| fillnull threat_object threat_object_type value="blah"
| lookup threat_check.csv threat_object AS threat_object threat_pal AS threat_object threat_object_type sources AS source OUTPUT threat_info threat_multiplier
| eval combined_ro = risk_object . "|" . risk_object_type
| fillnull risk_message value="" | fillnull threat_multiplier value="1" | eval risk_hash = md5(risk_message)
| eval threat_info = mvindex(threat_info,0) , threat_multiplier = mvindex(threat_multiplier,0)
| eventstats sum(calculated_risk_score) as total_risk_score max(calculated_risk_score) as single_risk_score by combined_ro source
| eventstats sum(total_risk_score) as supersum max(single_risk_score) as single_score by combined_ro source
| eval cross_total_score=if(supersum < single_score*2, supersum, single_score*2)
| eval cross_total_score = cross_total_score * threat_multiplier
| stats count as observed_count
    sum(calculated_risk_score) as total_risk_score
    max(calculated_risk_score) as single_risk_score
    values(threat_info) as threat_info
    values(risk_message) as risk_message
    values(risk_hash) as risk_hash
    values(threat_full) as threat_full
    values(threat_multiplier) as threat_multiplier
    values(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id
    dc(annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count
    values(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id,
    dc(annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count
    sum(cross_total_score) as cross_total_score
    values(tag) as tag
    dc(_time) AS dc_events 
by combined_ro, source, threat_object
| eval capped_risk_score=if(total_risk_score < single_risk_score*2, total_risk_score, single_risk_score*2)
| eval risk_object = mvindex(split(combined_ro, "|"), 0)
| eval risk_object_type = mvindex(split(combined_ro, "|"), 1)
| fields - combined_*
| eval threat_info = mvjoin(threat_info,"::::")
| eval threat_full = mvzip(threat_object,threat_info,"::::THREAT OBJECT PAIRS::::")
| rex mode=sed field=threat_full "s/::::/\n/g"
| eval total_risk_score = total_risk_score * threat_multiplier
| eval capped_risk_score = capped_risk_score * threat_multiplier
| eventstats values(risk_object) as related_objects by risk_hash
| stats 
    values(*) as *
    sum(total_risk_score) as total_risk_score 
    sum(capped_risk_score) as capped_risk_score
    values(cross_total_score) as cross_total_score
    sum(normalized_risk_score) as normalized_risk_score
    sum(normalcap_risk_score) as normalcap_risk_score
    dc(mitre_tactic_id) as mitre_tactic_id_count
    dc(mitre_technique_id) as mitre_technique_id_count
    dc(source) as source_count
    by risk_object
| eval cross_total_score = sum(cross_total_score) , cross_total_score = if(cross_total_score>=total_risk_score,capped_risk_score,cross_total_score)
| eval risk_score = capped_risk_score
| search risk_score > 100
| table risk_object risk_object_type risk_score cross_total_score capped_risk_score total_risk_score related_objects mitre_tactic_id_count mitre_tactic_id mitre_technique_id_count mitre_technique_id source_count source threat_full threat_object risk_message risk_hash
```

!!! note "The threat_check.csv has more fields than are utilized here, you may want to utilize more in the lookup OUTPUT section or as context for an investigation dashboard."

!!! note "risk_hash is utilized to see related_objects which have fired with the same events; you can use this as a throttling field instead of risk_object to prevent notables from firing with the same events on a user and a system."

I recommend utilizing "capped_risk_score" as our risk score as the code is above, however you may find that "cross_total_score" works better in some environments.

Please test this out in your environment and give me feedback! There are definitely multiple ways to trim this chia pet, but I wanted to give folks an idea of what was possible.

<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
