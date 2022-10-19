## Cap Contributing Risk Scores by Source

This logic will limit the number of times risk rules can contribute to the total score of a risk object:

```
| tstats summariesonly=true sum(All_Risk.calculated_risk_score) as summed_risk_score max(All_Risk.calculated_risk_score) as single_risk_score dc(source) as source_count count
 FROM datamodel=Risk.All_Risk
 WHERE All_Risk.risk_object_type="*" (All_Risk.risk_object="*" OR risk_object="*")
 BY All_Risk.risk_object All_Risk.risk_object_type source
| eval capped_risk_score=if(summed_risk_score < single_risk_score*3, summed_risk_score, single_risk_score*3)
| stats sum(capped_risk_score) as capped_risk_score sum(summed_risk_score) as summed_risk_score dc(source) as source sum(count) as count
 BY All_Risk.risk_object All_Risk.risk_object_type
| sort 1000 - risk_score
...
```

To cap the risk score contribution of a single source by 3x the highest score from that source. You may want to limit this to particular sources, but this is extra handy for noisy sources like EDR, DLP, or IDS. Thanks David Dorsey!
