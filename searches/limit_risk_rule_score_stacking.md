# Limit Contributions to Risk Score

This logic will limit the number of times a risk rule can contribute to the total score of a risk object:

```
| tstats summariesonly=false
 sum(All_Risk.calculated_risk_score) as summed_risk_score
 max(All_Risk.calculated_risk_score) as single_risk_score
 dc(source) as source_count,count
 FROM datamodel=Risk.All_Risk
 WHERE All_Risk.risk_object_type="*" (All_Risk.risk_object="*" OR risk_object="*")
 BY All_Risk.risk_object , All_Risk.risk_object_type , source
| eval capped_risk_score=if(summed_risk_score < single_risk*3, summed_risk_score, single_risk_score*3)
| stats sum(capped_risk_score) as risk_score, dc(source) as source, sum(count) as count by All_Risk.risk_object,All_Risk.risk_object_type
```
