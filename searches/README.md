# searches

These are some SPL techniques to get the most out of RBA by adding new features to your implementation or handling a common issue.

## [asset_and_identity_rir_logic.md](https://github.com/splunk/rba/blob/main/searches/asset_and_identity_rir_logic.md)
Adding this SPL into your Risk Incident Rules normalizes your risk object to a unique key in the Asset & Identity Framework; the primary advantage of this is throttling to prevent a Risk Incident Rule from firing on both a system and user that represent the same risk events.

## [limit_risk_rule_score_stacking.md](https://github.com/splunk/rba/blob/main/searches/limit_risk_rule_score_stacking.md)
This SPL for your Risk Score Risk Incident Rules ensures that a single correlation search can only contribute risk a total of three times (or whatever you would like). This is handy for reducing rapidly stacking risk which is common early in the RBA maturation process.

## [risk_guide_searches.md](https://github.com/splunk/rba/blob/main/searches/risk_guide_searches.md)
This is all of the handy SPL contained in the [Essential Guide to Risk Based Alerting](https://www.splunk.com/en_us/resources/the-essential-guide-to-risk-based-alerting.html); includes searches for finding noise, reducing noisy notables, and tuning risk rules.

## [risk_info_event_detail.md](https://github.com/splunk/rba/blob/main/searches/risk_info_event_detail.md)
This is one of my favorite additions to RBA; adding this macro to your risk rules creates a field called risk_info (which you can add to your Risk Datamodel) containing all of the useful fields your analyst might use for analysis. It's in JSON formatting which allows easy manipulation in SPL and excellent material for dashboards and unique drilldowns per field.

ADDITIONALLY, this frees risk_message to be used as a short and sweet summary rather than where you store all of the event detail. This lets Risk Notables tell a high level overview of events via risk_message, and is also handy to throttle or deduplicate by.

## [this_then_that_alerts.md](https://github.com/splunk/rba/blob/main/searches/this_then_that_alerts.md)
This is some simple SPL to organize risk events by risk_object and create risk rules which look for a specific sequence of events or chain of behaviors.
