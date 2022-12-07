# Throttle Alerts Which Have Already Been Reviewed

Because Risk Notables look at a period of time, it is common for a risk_object to keep creating notables as additional (and even duplicate) events roll in, as well as when events fall off as the time period moves forward. It is difficult to get around this with throttling, so we'll be using a Saved Search to store each Risk Notable's risk events and the analyst's status decision as a cross-reference for new notables and decide whether to create a new alert.

### KEEP IN MIND
Edits to the **Incident Review - Main** search ***may*** be replaced on updates to Enterprise Security; requiring you to make this minor edit again to regain this functionality. Ensure you have a step in your relevant process to check this search after an update.

## Extra Credit

If you utilize [risk_info](https://github.com/splunk/rba/blob/main/searches/risk_info_event_detail.md) so you have a short and sweet risk_message, you can add another level of granularity to your truth table (if you utilize risk_message for ALL of the event detail, it may be *too* granular and isn't as helpful for throttling). This is especially useful if you are creating risk events from a data source with its own signatures like EDR, IDS, or DLP. Because the initial truth table only looks at score and correlation rule, if you have one correlation rule importing numerous signatures, you may want to alert when a new signature within that source fires.

First, we'll create a new Calculated Field from risk_message in our Risk Datamodel called risk_hash with eval's md5() function, which bypasses the need to deal with special characters or other strangeness that might be in that field. If you haven't done this before - no worries - you just have to go to *Settings -> Data Models -> Risk Data Model -> Edit -> Edit Acceleration* and turn this off. Afterwards, you can *Create New -> Eval Expression* like this:

![creating risk_hash from md5(risk_message) in data model](https://github.com/splunk/rba/blob/main/searches/assets/calcfield_riskhash.png)

Don't forget to re-enable acceleration, and you may have to rebuild the data model from the *Settings -> Data Model* menu for this field to appear in your events.

Then we have to add this field into our Risk Incident Rules by adding this line to their initial SPL:

```
values(All_Risk.risk_hash) as risk_hashes
```

Now our Risk Notables will have a multi-value list of risk_message hashes which we can perform an additional truth table check by inserting this logic:

```
...
| eval previousStatus = case( like(previous_status_label, "%Closed%") , "non-malicious" , like(previous_status_label, "%Incident%") , "malicious" , true() , "F" )
| mvexpand risk_hashes
| eval matchHashes= if(risk_hashes != previous_risk_hashes , "F" , "T" )
| stats dc(matchHashes) as hashCheckFlag values(*) as * by _time risk_object event_hash 
| eval matchHashes = if(hashCheckFlag > 1 , "F" , matchHashes )
| mvexpand sources
...
```

Now if we add a "matchHashes" column to our truth table, we can introduce some additional granularity.
