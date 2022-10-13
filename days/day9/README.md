# 100 Days of Cloud Day 9

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6983876031027798016/)

## Post Contents

Day 9 of #100daysofcloud & #100daysofcybersecurity with a continuation of AWS DNS Firewall, this time focused on logging considerations and setup. As usual, #github link with permissions and the #python code in the comments.

DNSFW logging is a bit unique in how it is setup, as mentioned yesterday, DNSFW is part of the Route 53 Resolver ecosystem which means it is directly dependent on it not just for performing the DNS protection it also needs it for logging. That is to say there is not a dedicated logging source *strictly* for DNSFW - it is shared with the regular Query Logging.

Sources like VPC Flow Logs has its own logical construct, CloudFront can output to Kinesis Streams, WAF has a dedicated Kinesis Firehose output, but you'll need to conduct custom parsing to get any DNSFW related activities if that is all you care about. That also means your logs will be naturally chattier as EVERY DNS query is being captured, not just what specific logs you want for the Firewall itself.

Logging logic is stored within a Route 53 Resolver Query Logging Configuration. It is simply a store of a destination (S3, CloudWatch Logs or Kinesis Firehose) and associates VPCs. For collating across many Regions/Accounts S3 would be the logical choice, or using Firehose in between along with a Transformation to buffer the logs into Parquet for cheaper storage and easier querying.


For the Firewall-specific logs, there will be extra keys added into the JSON logging payload, notably "firewall_rule_action", using that as a filter/query basis will grab matching logs only. Most of your logs will be from updates, EDR callbacks, and the SSM Agent and normal queries for your application. Still a good idea to get basic stats on that, most people don't know their DNS traffic anyway.

Anyway, today's script will setup a very basic Query Logging Config, send logs to CloudWatch, and attach to all VPCs in your Region. Tomorrow we'll mess with some basic querying in Lambda and I'll give you an efficient way to unfold and query CloudWatch Logs streamed to Lambda.

Stay Dangerous

#awssecurity #dnssecurity #dns #bigdata #logging #siem #query #cloudsecurity #aws #awslogs #json #parquet