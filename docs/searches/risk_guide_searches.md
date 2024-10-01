# Essential RBA searches

!!! example "Handy SPL contained in the [Essential Guide to Risk Based Alerting](https://www.splunk.com/en_us/resources/the-essential-guide-to-risk-based-alerting.html){ target=_blank }."

## Determine Correlation Searches with High False/Benign Positive Rates

```shell linenums="1"
`notable`
| stats count(eval({==status_label==}="Incident")) as incident count(eval({==status_label==}="Resolved")) as closed
 BY source
| eval benign_rate = 1 - incident / (incident + closed)
| sort - benign_rate
```

???+ note
    Be sure to replace the `status_label` with whatever is used in your environment.

## Risk Rules Generating the Most Risk

```shell linenums="1"
| tstats summariesonly=false sum(All_Risk.calculated_risk_score)
   as risk_score,dc(All_Risk.risk_object)
   as risk_objects,count
 FROM datamodel=Risk.All_Risk
 WHERE * All_Risk.risk_object_type="*" (All_Risk.risk_object="*" OR risk_object="*")
 BY source
| sort 1000 - count risk_score
```

## Dig into Noisy Threat Objects

```shell linenums="1"
| tstats summariesonly=true count dc(All_Risk.risk_object) as dc_objects dc(All_Risk.src) as dc_src dc(All_Risk.dest) as dc_dest dc(All_Risk.user) as dc_users dc(All_Risk.user_bunit) as dc_bunit sum(All_Risk.calculated_risk_score) as risk_score values(source) as source
 FROM datamodel=Risk.All_Risk
 BY All_Risk.threat_object,All_Risk.threat_object_type
| `drop_dm_object_name("All_Risk")`
| sort 1000 - risk_score
```

## Find Noisiest Risk Rules in Risk Notables

```shell linenums="1"
index=notable eventtype=risk_notables
| stats count
 BY orig_source
| eventstats sum(count) as total
| eval percentage = round((count / total) * 100,2)
| sort - percentage
```

---

## Structural Changes

### Notable Suppression for QA Risk Notables

Add `| eval QA=1` to the end of your Risk Incident Rules, then go to Configure → Incident Management → Notable Event Suppressions, and create a new suppression for:

```shell title="QA mode"
index=notable QA=1
```

This will keep Risk Notables out of your Incident Review queue while you develop RBA.

### Create a Sandbox for Risk Rules away from Risk Notables

Create an eventtype called something like `QA` and have it apply a tag called `QA`, then add the following to your Risk Incident Rules.

```shell
...
WHERE NOT All_Risk.tag=QA
...
```

This keeps your curated risk ecology preserved so you can compare how many Risk Notables you would see if your QA content was added.

### Include Previous Notables in New Notables

If you create a lookup from a saved search called `Past7DayNotables.csv` where you store the previous time, status, and sources, you could include this in your Risk Incident Rules:

```shell linenums="1"
| lookup Past7DayNotables.csv risk_object OUTPUT prev_time prev_status prev_sources
| eval {==prev_alerts==} = prev_time." - ".prev_status." - ".prev_sources
```
???+ note
    Make sure to add `prev_alerts` to the Incident Review Settings page so this shows up in the Incident Review panel.

## Tuning

### Remove Results with a Lookup

Once you have a lookup built out, insert it into a search like this:

```shell linenums="1"
index=proxy http_method="POST" NOT
  [| inputlookup RR_Proxy_Allowlist.csv
  | fields Web.src Web.dest
  | rename Web.* AS *]
```

You could also do this with a datamodel:

```shell linenums="1"
| tstats summariesonly=t values(Web.dest) as dest from datamodel Web.Web where Web.http_method="POST" NOT
  [| inputlookup RR_Proxy_Allowlist.csv | fields Web.src Web.dest]
  by _time, Web.src
```

Using the Web datamodel field constraints as an example so we can properly exclude results from index or datamodel based risk rules.

### Adjust Risk Scores

- [Using eval](#using-eval)
- [Using lookup](#using-lookup)

#### Using `eval`

```shell linenums="1"
index=proxy signature=*
| table src user user_bunit dest signature http_code
| eval risk_score = case(
  signature="JS:Adware.Lnkr.A","10",
  signature="Win32.Adware.YTDownloader","0",
  NOT http_code="200","25",
  signature="Trojan.Win32.Emotet" AND NOT user_bunit="THREAT INTELLIGENCE","100"
  )
```

In this example, we are:

- Assigning the score of 10 for a signature that isn't generally bad but we still want to add a small amount of risk.
- Zeroing out the score for a signature of something a lot of our users have installed and we can't really control, but still want to observe is happening.
- Assigning the score of 25 for an unsuccessful HTTP connection.
- Assigning the score of 100 and potentially alerting directly in case we see malware from someone who **is not** on the Threat Intelligence team.
- Assigning a null() value in every other case to utilize the default risk score from the Risk Analysis action.

#### Using `lookup`

```shell linenums="1"
index=proxy signature=*
| table src user user_bunit dest signature http_code
| lookup RR_Proxy_Adjust.csv src user user_bunit dest signature http_code OUTPUTNEW risk_score
```

We can do the same with a lookup and as many relevant fields as we need for the most constrained exclusions.

### Dedup Similar Events from Counting Multiple Times in Risk Notables (Score)

```shell linenums="1"
...
 BY All_Risk.risk_object,All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| streamstats sum(risk_score) as original_score values(source) as sources values(risk_message) as risk_messages by risk_object
| eval adjust_score = case(
 source IN ("My Noisy Rule That Fires a Lot but I Still Want to Know About, Once", "My Other Really Useful Context Low Risk Rule"),"1",
 match(risk_message,"IDS - Rule Category 1.*|IDS - Rule Category 2.*") OR match(risk_message,"DLP - Rule Category 1.*|DLP - Rule Category 2.*"),"1",
 1=1,null())
| eval combine = coalesce(adjust_score,risk_message)
| dedup combine risk_score
| streamstats sum(risk_score) as risk_score values(sources) as source values(risk_messages) as risk_message by risk_object
...
```

For making sure similar detections on basically the same event only count once in our total risk score.

### Weight Events from Noisy Sources in Risk Notables (Metadata)

```shell linenums="1"
...
BY All_Risk.risk_object,All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| mvexpand source
| lookup RIRadjust-rule_weight.csv source OUTPUTNEW mitre_weight source_weight
| eval mitre_weight = if(isnotnull(mitre_weight),mitre_weight,"0")
| eval source_weight = if(isnotnull(source_weight),source_weight,"0")
| streamstats sum(mitre_weight) as mitre_weight_total sum(source_weight) as source_weight_total values(*) as * by risk_object risk_object_type
| eval mitre_tactic_id_count = mitre_tactic_id_count - mitre_weight_total
| eval source_count = source_count - source_weight_total
| eval "annotations.mitre_attack" = 'annotations.mitre_attack.mitre_technique_id'
| where mitre_tactic_id_count >= 3 and source_count >= 4
```

For tuning Risk Incident Rules that don't rely on an accretive score to alert, but still need a lever to tweak noisy sources. In our example lookup, we would include a value between 0 and 1 for each noisy source; IE 0.75 to only count a rule as 1/4 of a standard weight, 0.5 to only count as 1/2, etc.

---
<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4){ class="github-avatar"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
