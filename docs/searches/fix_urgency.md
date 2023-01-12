# Fix Urgency for Risk Notables

!!! tip "See the full walkthrough at [https://zachthesplunker.com/risk-notable-urgency/](https://zachthesplunker.com/risk-notable-urgency/){ target="_blank" }"

By default, a risk object's priority is not taken into account for the Urgency of a Notable event, even if it is configured in the A&I database. 

The Urgency field is a combination of an Asset/Identity's priority plus the severity of the event. The default Urgency Lookup can be found in Content Management in the Enterprise Security App.

## Simple Fix

```sh title="SPL to append to Risk Notables" linenums="1"
...
| eval 
    user=case(risk_object_type=="user", risk_object),
    src=case(isnull(user), risk_object)
```