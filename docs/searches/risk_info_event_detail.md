# Risk info field

## Create macro for risk_info field

You may want to keep risk_message relatively brief as a sort of high-level overview of a risk event, then utilize a new field to store details. We can create a macro called `risk_info(1)` to create a JSON-formatted field with this SPL:

```shell linenums="1" title="Macro definition"
eval risk_info = "{\"risk_info\":{"
| foreach $fields$
    [
    | eval <<FIELD>>=if(isnull(<<FIELD>>), "unknown", <<FIELD>>)
    ```Preparing json array if FIELD is multivalue, otherwise simple json value```
    | eval json=if(mvcount(<<FIELD>>)>1,mv_to_json_array(mvdedup(<<FIELD>>)),"\"".<<FIELD>>."\"") 
    | eval risk_info=risk_info."\""."<<FIELD>>"."\": ".json.","
    ]
| rex mode=sed field=risk_info "s/,$/}}/"
| fields - json
```

!!! tip ""
    <span style="font-size: 1.5em">:raised_hands:  </span> Many thanks to [RedTigR](/contributing/contributors) on the RBA Slack for providing the multi-value friendly version of this macro.

Utilizing the macro like `risk_info("field1,field2,field3,etc")` to give us a JSON formatted field with any of the fields we like.

And then if we wanted to break this out in a dashboard we could use `spath` to break out fields into their own columns, or a rex command like this:

!!! example

    ```shell
    | rex field=risk_info max_match=100 "(?<risk_info2>\"\w+\":\s*((?:(?<!\\\)\"[^\"]*\"|\[[^\]]*\]))(?=,|\s*}))"
    ```

To break out each field as a multi-value on their own line in the same column. It looks really pretty, and you can even use `$click.value2$` to determine exactly which MV field was clicked and utilize different drilldowns per field, for example.

## Extracting existing fields from risk events into risk_info field

!!! info "Assumption"
    Your risk rules are outputting specific details in addition to the risk fields (e.g. `risk_message`, `risk_object` etc.)

The following search replaces the `View the individual Risk Attributions` drilldown within a risk incident rule. It allows us to dynamically bring the output of each individual risk rule in a concise manner.

The aim of this is to minimize pivoting when performing the initial assessment of a risk incident while keeping the notable and `risk_message` field concise.

``` shell linenums="1"
index=risk
| search risk_object=$risk_object$
| rename annotations.mitre_attack.mitre_tactic_id AS mitre_tactic_id, annotations.mitre_attack.mitre_tactic AS mitre_tactic
{==| rex field=_raw==} max_match=0 "(?<risk_info>[^\=]+\=\"([^\"]+\")+?)((, )|$)"
| eval risk_info=mvfilter(NOT match(risk_info, "^(annotations)|(info_)|(savedsearch_description)|(risk_)|(orig_time)|(([0-9]+, )?search_name)"))
| table _time, source, risk_object, risk_score, risk_message, risk_info, risk_object_type, mitre_tactic_id, mitre_tactic
| eval {==calculated_risk_score==}=risk_score
| sort _time
```

Breaking down some decisions:

- `| rex field=_raw` instead of `| foreach *` since Splunk adds in additional fields which aren't in the original risk rule output. This was made so the output is as concise and as relevant as possible. However, foreach is another method and it isn't reliant on regex.
- `calculated_risk_score` is a [required field](https://docs.splunk.com/Documentation/ES/latest/User/Triagenotableevents#Use_custom_risk_notables_to_identify_threats){ target=_blank } for the drilldown so it displays properly in the Risk Events panel.
- If you are providing _time in your risk rules, you could rename `_time` to `observation_time` and `orig_time` to `_time` for a more accurate chronological order of events.
- The datamodel could be used, but if you wanted accelerated searching via `tstats` you would need to customize it in some way such as including the `_raw` field, which may be costly. Creating a risk_info field with the macro above would be more efficient.

---
<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4){ class="github-avatar"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="RedTigR">
        <img class="github-avatar" src="https://ca.slack-edge.com/TLRQHBNKD-UUHMZ9CL8-0e1195c46b5b-512"/>
    </a>
    <span class="zts-tooltip-text">@RedTigR</span>
</div>
<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="elusive-mesmer">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/117061618?v=4){ class="github-avatar"/>
    </a>
    <span class="zts-tooltip-text">@elusive-mesmer</span>
</div>