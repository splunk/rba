# Storing event detail in risk_info field
You may want to keep risk_message relatively brief as a sort of high-level overview of a risk event, then utilize a new field to store details. We can create a macro called `risk_info(1)` to create a JSON-formatted field with this SPL:

```
eval risk_info = "{\"risk_info\":{" 
| foreach $fields$ 
[| eval <<FIELD>>=if(isnull(<<FIELD>>), "unknown", <<FIELD>>), risk_info=risk_info."\""."<<FIELD>>"."\":\"".<<FIELD>>."\","]
| rex mode=sed field=risk_info "s/,$/}}/"
```

Utilizing the macro like `risk_info("field1,field2,field3,etc")` to give us a JSON formatted field with any of the fields we like.

And then if we wanted to break this out in a dashboard we could use spath to break out fields into their own columns, or a rex command like this:

```
| rex field=risk_info max_match=100 "(?<risk_info>\"[a-zA-Z_]+\"\:(|\s)\"[^\"]+\")[\,\}]"
```

To break out each field as a multi-value on their own line in the same column. It looks really pretty, and you can even use $click.value2$ to determine exactly which MV field was clicked and utilize different drilldowns per field, for example.
