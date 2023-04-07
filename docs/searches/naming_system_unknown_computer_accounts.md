# Naming SYSTEM / Unknown / Computer Accounts - The SEAL Method 

Computer accounts are used by Active Directory to authenticate machines to the domain, and RBA detections may find behavior in a log where the user account is simply listed as "SYSTEM" or even left blank because it is the computer account. This method renames the account to distinguish it as **host$** from the noise of "SYSTEM" or "unknown". It can also be tied into the Asset & Identify framework and contribute to detections on user risk objects.

## Steps

Navigate to **Settings > Fields > Calculated Fields > Add New**

Setting | Value
------- | -----
**Source** | `XmlWinEventLog:Security`
**Source** | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
**Name** | `user`
**Eval Expression** | `if(user="SYSTEM" OR user="-",'host'+"$",'user')`

???+ warning "Conflicting knowledge objects - [Sysmon TA][sysmon-ta]{ target="_blank" }"
    We have to be careful with existing order of knowledge objects and calculated fields. The [Sysmon TA][sysmon-ta]{ target="_blank" } already has a `user = ""` calculated field which we can update as follows:
    
    ``` shell title="Existing:"
    user = upper(case(
        NOT isnull(User) AND NOT User IN ("-"), replace(User, "(.*)\\\(.+)$","\2"),
        NOT isnull(SourceUser) AND NOT isnull(TargetUser) AND SourceUser==TargetUser, replace(SourceUser, "(.*)\\\(.+)$","\2")
        ))
    ```

    ``` shell title="Update to:"
    user = upper(case(
        match(User,".+\\\SYSTEM"), host."$",
        NOT isnull(User) AND NOT User IN ("-"), replace(User, "(.*)\\\(.+)$","\2"),
        NOT isnull(SourceUser) AND NOT isnull(TargetUser) AND SourceUser==TargetUser, replace(SourceUser, "(.*)\\\(.+)$","\2")
        ))
    ```

## Extra Credit

Not going to map this entire process due to how different it can be in each environment, but you can now add the computer account to your Identity lookup to aggregate with other user accounts. For example, you might take the fields `nt_host` and `owner` from your Asset lookup (asset_lookup_by_str), then map `owner` to `email` in the Identity lookup (identity_lookup_expanded). If you make a saved search that outputs a CSV, you can now use that to add fields into your Identity lookup.

---
<small>Authors</small>

<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="Dean Luxton">
        <img class="github-avatar" src="../../assets/authors/dean_luxton_linkedin.jpg"/>
    </a>
    <span class="zts-tooltip-text">@Dean Luxton</span>
</div>
<div class="zts-tooltip">
    <a class="zts-author" href="../../contributing/contributors" target="_blank" alt="StevenD">
        <img class="github-avatar" src="https://avatars.githubusercontent.com/u/38897662?v=4"/>
    </a>
    <span class="zts-tooltip-text">@StevenD</span>
</div>

[sysmon-ta]: https://splunkbase.splunk.com/app/5709