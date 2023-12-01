# Additional Threat Object Types

Increasing the number of threat object types you track in Risk Rules can be really helpful for tuning noisy alerts, threat hunting on anomalous combinations, and automating SOAR enrichment to unique threat object types. Haylee and Stuart's [Threat Object Fun dashboards](https://splunkbase.splunk.com/app/6917) can be helpful for all three.

Some potential threat_object_types to keep in mind when creating risk rules:

source | threat_object_type
email, endpoint, network, proxy | ip
email, endpoint, proxy | src_user
email, endpoint, proxy | user
endpoint, email | file_hash
endpoint, email | file_name
endpoint, proxy | domain
endpoint, proxy | url
email | email_subject
email | email_body
endpoint | command
endpoint | parent_process
endpoint | parent_process_name
endpoint | process
endpoint | process_file_name
endpoint | process_hash
endpoint | process_name
endpoint | registry_path
endpoint | registry_value_name
endpoint | registry_value_text
endpoint | service
endpoint | service_dll_file_hash
endpoint | service_file_hash
proxy | certificate_common_name
proxy | certificate_organization
proxy | certificate_serial
proxy | certificate_unit
proxy | http_referrer
proxy | http_user_agent

You could also use open-source server handshake hashing algorithms like [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FoxIO-LLC/ja4), [JARM](https://github.com/salesforce/jarm), or [CYU](https://github.com/salesforce/GQUIC_Protocol_Analyzer) to identify anomalous server handshakes and potentially include:

ja3_hash
ja3s_hash
ja4_hash
jarm_hash
cyu_hash
asn
