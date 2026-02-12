# Enterprise-Cloud-Attack-Surface-Detection-Engineering-Project-AWS-MITRE-ATT-CK-SIEM-
Fortune 500–aligned Threat Intelligence &amp; AWS cloud attack surface assessment with SIEM-ready detection engineering use cases, ransomware threat modeling, and MITRE ATT&amp;CK mapping.
index=aws_cloudtrail eventName=ConsoleLogin
| stats count by userIdentity.userName, sourceIPAddress, awsRegion
| eventstats dc(sourceIPAddress) as ip_count by userIdentity.userName
| where ip_count > 3
| table _time, userIdentity.userName, sourceIPAddress, awsRegion

index=authentication_logs
| stats earliest(_time) as first_login latest(_time) as last_login by user, src_ip, country
| eval time_diff=last_login-first_login
| where time_diff < 14400 AND country != previous(country)

AWSCloudTrail
| where EventName == "ConsoleLogin"
| summarize LoginCount=count(), IPCount=dcount(SourceIpAddress) by UserIdentityUserName
| where IPCount > 3

DnsEvents
| where QueryName contains "zoho-secure" or QueryName contains "zoho-login"
| summarize count() by QueryName, ClientIP

index=auth_logs action=failure
| stats count by src_ip, user
| where count > 15
| sort -count
