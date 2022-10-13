# 100 Days of Cloud Day 10

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6984155402036727809/)

## Post Contents

Day 10 of #100daysofcloud & #100daysofcybersecurity delving more into our #NetSec topic around #AWS #DNS #Firewall and logging activity from it. As usual, GitHub with the permissions and code snippets as needed will be within.

Today you'll need to put a bit of sweat equity in, you don't learn anything being told all of the answers, that's a theme I'll try to go for - plus these small bite-sized posts are defeated if every single one needed exhaustive setup. So hopefully you're comfortable with creating CloudWatch Logs Subscription Filters to Lambda & setting up permissions as needed.

DNS Query Logging in AWS will only add in DNS Firewall information when a match against a Rule is determined. This makes parsing a bit annoying as the logic will be centered on handling exceptions from the fact a piece of the log is missing. Outside of that - working with CloudWatch Logs streamed to Lambda is annoying. You get base64 encoded/zipped/stringified data in that needs to be decoded, decompressed and loaded into a useable format.

Every log type via CloudWatch Logs has it's own nuances. For DNS Query Logging as you loop through the payload you need to access the logs within a "message" key which is another stringified JSON object. This Lambda function handles all of this logic for you and can expanded for use with other CWL sources such as API Gateway and VPC Flow Logs. The function is also written properly, with business logic outside the handler, globals outside of the functions, and limited crap loaded into memory.

The Query Logs are a decently rich data source - provided basic orienteering intel, the action and domain list/rule group that DNSFW matched, and the source and query destination with some other DNS-related info. The logic here is very basic and just prints out what happened when a rule is matched. I put some minimal code to send the message to SNS if you wanted to do that.

This brings up Security #ChatOps - for DNS based threats - especially if they're from known or suspected C2 nodes/malware domains/mining pools you'd want to be alerted immediately especially for COUNT actions so you can deploy countermeasures. The more services chained together the more latency you pick up. You also want to ensure you do not pummel your IR Analysts with a ton of noise and that an ALERT is treated as such - don't just throw it into a SIEM and hope someone triages correctly.

As either a SOC Manager or a security leader in general you'll need to understand this prioritization & psychological impact it'll have. Push-based/pager style alert should really be reserved for something (potentially) terrible and not routine signaling.

Tomorrow we'll do a bit of enrichment, IOC garbage on Day 12, and continue through the #NetSec stuff until we're all exhausted.

Stay Dangerous

#cloudsecurity #awssecurity #infosec