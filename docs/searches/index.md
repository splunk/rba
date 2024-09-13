# Helpful Searches

These are some SPL techniques to get the most out of RBA by adding new features to your implementation or handling a common issue.

## [Chaining behaviors](./this_then_that_alerts.md)

This is some simple SPL to organize risk events by risk_object and create risk rules which look for a specific sequence of events or chain of behaviors.

## [Deduplicate Notables](./deduplicate_notables.md)

This feature will drastically reduce the number of duplicate Risk Notables by removing alerts where events are basically the same, already reviewed, or another Risk Incident Rule has already fired for.

## [Dynamic Drilldowns](./dynamic_drilldowns.md)

If you're utilizing a custom risk notable investigation dashboard, it can be incredibly helpful for each risk event source to have its own drilldown. Thanks to Donald Murchison from the RBA Slack for contributing this method, which is explained in more detail in this [blog post](https://medium.com/@donemurch/lookup-to-drilldown-building-dynamic-searches-for-triaging-risk-notables-in-splunk-87c976711f7a){ target="blank" }.

## [Essential RBA searches](./risk_guide_searches.md)

This is all of the handy SPL contained in the [Essential Guide to Risk Based Alerting](https://www.splunk.com/en_us/resources/the-essential-guide-to-risk-based-alerting.html){ target=_blank }; includes searches for finding noise, reducing noisy notables, and tuning risk rules.

## [Integrate A&I with RiR](./asset_and_identity_rir_logic.md)

Adding this SPL into your Risk Incident Rules normalizes your risk object to a unique key in the Asset & Identity Framework; the primary advantage of this is throttling to prevent a Risk Incident Rule from firing on both a system and user that represent the same risk events.

## [Limit score stacking](./limit_score_stacking.md)

This SPL for your Risk Score Risk Incident Rules ensures that a single correlation search can only contribute risk a total of three times (or whatever you would like). This is handy for reducing rapidly stacking risk which is common early in the RBA maturation process.

## [Naming SYSTEM/Unknown/Computer Accounts](./naming_system_unknown_computer_accounts.md)

Computer accounts are used by Active Directory to authenticate machines to the domain, and RBA detections may find behavior in a log where the user account is simply listed as "SYSTEM" or even left blank because it is the computer account. This method renames the account to distinguish it as host$ from the noise of "SYSTEM" or "unknown". It can also be tied into the Asset & Identify framework and contribute to detections on user risk objects.

## [Risk Incident Rule Ideas](./risk_incident_rule_ideas.md)

Alternative ways to alert from the risk index that you may find useful. Later searches will be relying on the base search found in the "Capped Risk Score by Source" approach.

## [Risk info field](./risk_info_event_detail.md)

This is one of my favorite additions to RBA; adding this macro to your risk rules creates a field called risk_info (which you can add to your Risk Datamodel) containing all of the useful fields your analyst might use for analysis. It's in JSON formatting which allows easy manipulation in SPL and excellent material for dashboards and unique drilldowns per field.

ADDITIONALLY, this frees risk_message to be used as a short and sweet summary rather than where you store all of the event detail. This lets Risk Notables tell a high level overview of events via risk_message, and is also handy to throttle or deduplicate by.

## [Risk Notable History](./risk_notable_history.md)

Tyler Younger from the RBA Slack contributed this handy method for including some useful history of risk notables for that risk object when it fires. I played with it a bit and created a version I might use in a dashboard for additional context. You should check with your analysts to see what would be most helpful for them.

## [Threat Object Prevalence](./threat_object_prevalence.md)

One of the great features in RBA is knowing how often something has occurred in an environment; generally, the more rare or anomalous something is, the more likely it is to be malicious. The threat object drilldown in the sample [Risk Investigation Dashboard](https://splunk.github.io/rba/dashboards/risk_investigation/){ target="blank" } is designed to offer an analyst that context, but with a simple saved search, we could use that context in our Risk Notables as well.

## [Threat Object Types](./threat_object_types.md)

Increasing the number of threat object types you track in Risk Rules can be really helpful for tuning noisy alerts, threat hunting on anomalous combinations, and automating SOAR enrichment to unique threat object types. Haylee and Stuart's [Threat Object Fun dashboards](https://splunkbase.splunk.com/app/6917){ target="blank" } can be helpful for all three.

## [UBA-lite with Basic Statistics](./uba-lite_with_statistics.md)

By comparing entity activity against itself or entities in a peer group (IE business unit, asset category, etc), you can create rules that offer anomaly detection capabilities similar to a UBA/UEBA solution.