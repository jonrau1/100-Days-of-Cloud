# 100 Days of Cloud Day 18

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6987141366212349952/)

## Post Contents

Day 18 of #100daysofcloud & #100daysofcybersecurity as we continue our AWS WAF journey, we've arrived at setting up logging. There are multiple ways to set up logging in AWS WAFv2 now which we'll go over, but the script focuses on S3 as it's the most straight forward.

First option is not logging, and simply relying on CloudWatch Metrics to tell when requests are allowed/blocked and only analyzing the downstream logs from your CDNs/Load Balancers/Applications. Plenty of merit to that, especially if you do not want to onboard what will be an expensive, chatty log source if you have consistent high-volume access.

The next options are Kinesis Firehose (the "OG" option), Amazon S3 directly, and CloudWatch Logs. Kinesis Firehose used to be the only way to do it and was fine inasmuch as it auto-scales, you could technically crack open the records from the Delivery Stream with a Lambda, and you can change the compression and buffering rate to combine the logs into more efficient formats. The other nice thing is not needing to send it to S3 directly and instead opting for an API destination or a dedicated APM tool such as DataDog.

If you do not mind GZIP JSON, going straight through to S3 is another valid option. I have a feeling AWS transparently uses it away from you as the logs are still bundled and compressed, but JSON is always the base element. Then there is CloudWatch Logs which you already have an example for from the Days we went over DNS Firewall.

It will all come down to what you want to do with the logs and where you want to send them. As far as intel you can glean most of the log is telling you what Managed/Custom Rule Groups matched (if any) and basic information from the requester such as User-Agent, IP address, Country Code, and other included headers. The URI is also given so for the most basic OSINT you can see if adversaries are combing specific URIs (login.aspx, /admin, /sidedoor.do, etc.) and get an approximation of where they're coming from.

There are filters within the Logging Configuration too - you may want to drop ALLOWs or drop BLOCKs (since it's blocked already) or a mixture. You can also redact certain elements of the log from coming back if you have privacy or other regulatory obligations. This can minimize PII leakage and also the storage & processing size.

There is not much real-time hunting you can do, but nothing wrong with NOT storing it at all.

Either way, the script will create an S3 Bucket, add the policy, attach it to all of your WAFs and you can provide a variable that will do the worlds laziest bruteforce attempt to generate quick logs for you. Feel free to edit it out. There's a commented-out section for a logging filter if you wanted to apply that as well.

Tomorrow we'll look into light enrichment, flattening and conversion to Parquet.

Stay Dangerous

#cloudsecurity #waf #redteam #logging #siem #awssecurity