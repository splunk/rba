# Deduplicate Notable Events

This feature will drastically reduce the number of duplicate Risk Notables by removing alerts where events are basically the same, already reviewed, or another Risk Incident Rule has already fired for.

There are two options to deduplicate notable events. Both options will reduce duplicate events but may differ in complexity. 

## [Option I](./deduplicate_notables/)

This is the original method to deduplicate events and is referenced in[ Haylee's guide](https://www.splunk.com/en_us/form/the-essential-guide-to-risk-based-alerting.html){ target="blank" }. 

## [Option II](./deduplicate_notables_2/)

This option adds some complexity, however, provides more information and better deduplication.