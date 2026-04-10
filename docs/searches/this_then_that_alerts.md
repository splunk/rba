# Detect Chain of Behaviors

To make a risk rule that looks for two rules firing close together, we can use `sort` followed by the `autoregress` command within a certain duration:

```shell linenums="1"
index=risk sourcetype=stash search_name="Search1" OR search_name="Search2"
| sort by user _time | dedup _time search_name user
| delta _time as gap
| autoregress search_name as prev_search
| autoregress user as prev_user
| where user = prev_user
| table _time gap src user prev_user search_name prev_search
| where ((search_name="Search1" OR search_name="Search2") AND (prev_search="Search1" OR prev_search="Search2") AND gap<600)
```

The benefit of not doing this in a single search is you still have the individual risk events as useful observations, and then can add more risk when observed together, or tweak risk down for noisy events without "allowlisting" altogether.

[Ryan Moss from Verizon also spoke about using Analytic Stories with RBA](https://conf.splunk.com/files/2023/recordings/SEC1402A.mp4) which is another excellent method for low volume, high fidelity chained detections.

# Dynamic Scoring on Previous Behavior

Had someone reach out with a unique use case, made extra unique by the fact it was an "Improbable Access" rule that fired on system with multiple users, what they wanted was for the initial score to be 50, and then +5 for each additional user observed on the machine. So if they have that rule just score as zero, here's the madness I concocted:

```shell linenums="1"
index=risk sourcetype=stash search_name="Improbable Access Rulename"
| sort by src _time | dedup _time search_name src
| eval usercount = mvcount(users)
| autoregress usercount as prev_count
| autoregress src as prev_src
| table _time gap src users prev_src usercount prev_count search_name
| eval prev_src = if(prev_src!=src,null(),prev_src)
| delta usercount AS increase
| eval src_event = src."_src"
| eval users = mvappend(src_event,users)
| mvexpand users
| eval risk_score = case(
isnull(prev_src),"50",
usercount>prev_count,5*increase,
usercount=prev_count,"0",
true(),"0")
| eval src = if(match(users,".*_src"),src,null())
| rex field=src mode=sed "s/(.*)_src/\1/g"
```

The real madness was ensuring that the system only got risk once and however I tried to cut it with throttling, src would still get risk score multiplied by the number of users on it. So we find out rule, we count the users, we autoregress, we null() the prev_src field if it's not itself (and becomes a handy indicator this is the first time it fired in our timeframe), measure the increase in users, bring our src into the userlist so we get a unique row for it when we mvexpand, now we score 50 for the first event, if the count is higher than the previous event we do 5 * the_increase, then null out the src for our actual user events and trim our suffix for our actual src event.

Now in our detection we can use risk_object_type=system with src and risk_object_type=user with our users field. Hope this gives you some ideas!

---
<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="7thdrxn - Haylee Mills">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/12771156?v=4){ class="github-avatar"/>
    </a>
    <span class="zts-tooltip-text">@7thdrxn - Haylee Mills</span>
</div>
