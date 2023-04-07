# Naming SYSTEM / Unknown / Computer Accounts - The SEAL Method 

Computer accounts are used by Active Directory to authenticate machines to the domain, and RBA detections may find behavior in a log where the user account is simply listed as "SYSTEM" or even left blank because it is the computer account. This method renames the account to distinguish it as **host$** from the noise of "SYSTEM" or "unknown". It can also be tied into the Asset & Identify framework and contribute to detections on user risk objects.

## Steps

Navigate to Settings > Fields > Calculated Fields > Add New

Setting | Value
------- | -----
**Source** | `XmlWinEventLog:Security`
**Source** | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
**Name** | `user`
**Eval Expression** | `if(user="SYSTEM" OR user="-",'host'+"$",'user')`


## Extra Credit

Not going to map this entire process due to how different it can be in each environment, but you can now add the computer account to your Identity lookup to aggregate with other user accounts. For example, you might take the fields `nt_host` and `owner` from your Asset lookup (asset_lookup_by_str), then map `owner` to `email` in the Identity lookup (identity_lookup_expanded). If you make a saved search that outputs a CSV, you can now use that to add fields into your Identity lookup.

---
<small>Authors</small>

[![Dean Luxton](https://media.licdn.com/dms/image/D5603AQEwm5QYVmn-Dw/profile-displayphoto-shrink_800_800/0/1664578674505?e=2147483647&v=beta&t=mcDIkVlKDgC2bhb0GdDhJNOHuN04esAaGYO0-NjyM8c){ class="github-avatar" }](../contributing/contributors.md "Credit: @Dean Luxton")