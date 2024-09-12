# UBA-lite with Basic Statistics

!!! note
    This is just an example using basic statistics and a CSV lookup. You can make this much more efficient at scale by utilizing a KVstore OR outputting to a summary index / accelerated report and searching back on that data.

By comparing entity activity against itself or entities in a peer group (IE business unit, asset category, etc), you can create rules that offer anomaly detection capabilities similar to a UBA/UEBA solution. In RBA, you might use this as rules that generate risk events, or a field to use as a risk factor, or even just tags for the entity so that when you're investigating a risk-based alert you have an idea that this entity has been behaving erratically compared to various standards of behavior.

## Example: Event Count Variance per Category by Risk Object

In this case, we are utilizing the "category" field from the Asset & Identity Framework. We are specifically looking at the identity lookup(`identity_lookup_expanded`) and not the asset lookup(`asset_lookup_by_str/cidr`).

In this example, I'm creating sample data with two queries, one with relative_time(-7d) and one now(). In actual practice,you want to run something like this weekly on the past week to fill out a lookup (`baseline_risk_events.csv`) which will measure event counts per risk object and category week after week, to use for average/stdev statistics. You could also *actually* run this query on a timerange of the previous week so that the `ran=relative_time(now(),"-7d")` is accurate.

```shell linenums="1"
index=risk
| stats count by risk_object date_wday
| xyseries risk_object date_wday count
| lookup identity_lookup_expanded identity AS risk_object OUTPUT category
| fillnull category value="unknown"
| eval ran=relative_time(now(), "-7d") , ran=round(ran,0)
| fields ran category risk_object sunday monday tuesday wednesday thursday friday saturday
| eval retain=if(ran >= relative_time(now(), "-90d@d"), 1, 0)
| where retain=1
| dedup ran risk_object category
| outputlookup baseline_risk_events.csv
```

This first search gives us the initial lookup. The second search below loads that lookup and adds another row with the timestamp of `now()`. In production, the following would be your saved search; the previous search was only to make sample data and an initial CSV lookup. You'll see the logic here which trims entries that are older than 90 days (`where retain=1`) to prevent the lookup from forever becoming larger as a saved search.

```shell linenums="1"
index=risk
| stats count by risk_object date_wday
| xyseries risk_object date_wday count
| lookup identity_lookup_expanded identity AS risk_object OUTPUT category
| fillnull category value="unknown"
| eval ran=now()
| fields ran category risk_object sunday monday tuesday wednesday thursday friday saturday
| inputlookup append=true baseline_risk_events.csv
| eval retain=if(ran >= relative_time(now(), "-90d@d"), 1, 0)
| where retain=1
| dedup ran risk_object category
| outputlookup baseline_risk_events.csv
```

#### Searching our Behavioral Data

For this detection, we'll be counting events from identities by category, so we can see when an entity within that category is behaving outside of the normal event count for its peer group. You can use another field than category, just make sure to replace it through all of the queries.

Our first search is to generate something more meaningful (avg+stdev/category) we can actually use for a detection.

```shell linenums="1"
| inputlookup baseline_risk_events.csv
| fillnull value="0"
| fields - retain ran
| eval week = sunday + monday + tuesday + wednesday + thursday + friday + saturday
| rename sunday as sun monday as mon tuesday as tue wednesday as wed thursday as thu friday as fri saturday as sat
| makemv tokenizer="([^\r\n]+)(\r\n)?" category
| mvexpand category
| stats list(*) as * by category
| stats avg(*) as avg_* stdev(*) as stdev_* by category
| foreach sun mon tue wed thu fri sat week [eval lb_<<FIELD>>=avg_<<FIELD>>-stdev_<<FIELD>>*2 , ub_<<FIELD>>=avg_<<FIELD>>+stdev_<<FIELD>>*2]
| outputlookup event_count_by_category.csv
```

This creates an average, stdev, and upper bound (avg+stdev*2) for each day of the week and the entire week per category. The ` makemv tokenizer + mvexpand` lines create multiple entries when a risk_object is part of multiple categories.

Now we can utilize this data. As I mentioned above, you may want to use this as a risk rule, or maybe a tag on the asset/identity indicating the entity is behaving anomalously compared to previous weeks, or maybe that tag as a risk factor which means events going forward that week/month/time will have increased risk on that entity. Also, you will have to determine how often to run this. You could run it weekly or maybe at the end of the day so that the risk event / risk factor is applied to events the following day... it's really hard to give exact guidance here and you will have to decide what makes sense for you.

Regardless, sample SPL to detect variance from peers by category:

```shell linenums="1"
index=risk
| stats count by risk_object date_wday
| eventstats sum(count) as week_count dc(date_wday) as days_count by risk_object
| lookup identity_lookup_expanded identity AS risk_object OUTPUT category
| fillnull category value="unknown"
| mvexpand category
| lookup event_count_by_category.csv category OUTPUTNEW ub_sun ub_mon ub_tue ub_wed ub_thu ub_fri ub_sat ub_week
| foreach ub_* [eval <<FIELD>>=round(<<FIELD>>,0)]
| eval outlier_count = 0
| eval outlier_count = if(date_wday="sunday" AND count>ub_sun,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="monday" AND count>ub_mon,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="tuesday" AND count>ub_tue,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="wednesday" AND count>ub_wed,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="thursday" AND count>ub_thu,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="friday" AND count>ub_fri,outlier_count+1,outlier_count)
| eval outlier_count = if(date_wday="saturday" AND count>ub_sat,outlier_count+1,outlier_count)
| eval outlier_week = if(week_count>ub_week,"yes","no")
| eval day_count = date_wday." - ".count
| stats sum(outlier_count) as outlier_count values(outlier_week) as outlier_week values(week_count) as week_count values(day_count) as day_count values(ub_sun) as ub_sun values(ub_mon) as ub_mon values(ub_tue) as ub_tue values(ub_wed) as ub_wed values(ub_thu) as ub_thu values(ub_fri) as ub_fri values(ub_sat) as ub_sat values(ub_week) as ub_week by risk_object category
| where outlier_count>0 OR outlier_week=”yes”
```

This is just one way of doing outliers, also. This will output the number of outliers in the previous week for that category (`outlier_count`) and if the total number of events in that week was an outlier (`outlier_week`).

## Conclusion

I hope that gives you some ideas for UBA-lite content. This will not compare with the ML of a true UBA solution, but is very useful context, and basic statistics can still be very powerful for analysis and threat detection. If you develop your own, please share!

---
<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4){ class="github-avatar"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
