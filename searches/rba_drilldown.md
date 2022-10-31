# Risk incident drilldown

_Assumption:_ Your risk rules are outputting specific details in addition to the risk fields (e.g. `risk_message`, `risk_object` etc.)

The following search replaces the `View the individual Risk Attributions` drilldown within a risk incident rule. It allows us to dynamically bring the output of each individual risk rule in a concise manner.

The aim of this is to minimise pivoting when performing the initial assessment of a risk incident while keeping the notable and `risk_message` field concise.

``` SPL
index=risk 
| search risk_object=$risk_object$
| rename annotations.mitre_attack.mitre_tactic_id AS mitre_tactic_id, annotations.mitre_attack.mitre_tactic AS mitre_tactic
| rex field=_raw max_match=0 "(?<risk_info>[^\=]+\=\"([^\"]+\")+?)((, )|$)"
| table _time, source, risk_object, risk_score, risk_message, risk_info, risk_object_type, mitre_tactic_id, mitre_tactic
| eval calculated_risk_score=risk_score
| sort _time
```

Breaking down some decisions:

* `| rex field=_raw` instead of `| foreach *` since Splunk adds in additional fields which aren't in the original risk rule output. This was made so the output is as concise and as relevant as possible. However, foreach is another method and it isn't reliant on regex.
* `calculated_risk_score` is a required field for the drilldown so it displays properly in the Risk Events panel - https://docs.splunk.com/Documentation/ES/7.0.2/User/Triagenotableevents#Use_custom_risk_notables_to_identify_threats
* If you are providing _time in your risk rules, you could rename `_time` to `observation_time` and `orig_time` to `_time` for a more accurate chronological order of events
* The data model could be used, but if you wanted accelerated seaching via `tstats` you would need to customise it in some way such as including the `_raw` field. Customisation should not be taken lightly.
