# 100 Days of Cloud Day 12

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6984932402322100224/)

## Post Contents

Hello friends, hope everyone not working today is having a restful Sunday. It is Day 12 of #100daysofcloud & #100daysofcybersecurity continuing on the thread of possible real-time enrichment use cases on top of AWS DNSFW Query Logs.

Starting on Day 10 you learned how to deploy and optimize a Lambda function to parse CloudWatch Logs and exit if a desired state or item was not found (to lower costs & concurrent invocations). Day 11 saw as utilizing the Python `socket` module for a very basic way of finding the IP under a domain, today we continue to expand the Lambda function with a new "geo-intelligence" function.

Calling it that is insulting to real #GEOINT work that analysts do out there, but really its more akin to #OSINT, finding the geographical location corresponding to an IP address as well as the ASN, ORG and ISP. This information is mostly used to paint pretty map pictures for gimmicky websites and SOC/NOC dashboards but there can be some usage of it.

ISP/ASN/ORG can tell you about the nature of the hosting - is it Amazon, CloudFlare, Censys, Alibaba, Sinnet, etc? These usually correspond to a Country. Maybe you have data embargo concerns that need to be enforced due to contractual or regulatory obligations. Maybe you don't do business in a specific country but someone INSIDE your network is communicating outbound - that may be an issue. Maybe you're tired of chasing IOCs by country and need justification to block an entire country on your WAF or CDN (that would be more for inbound, not outbound connections).

Some data "tricks" exist within the code, namely planning for conditions when you don't get data back (an IP or the GEOINT). Always ensure your downstream datastore / BI tool can support a specific data type. DynamoDB doesn't like Floats but it's fine with Null/NONE. QuickSight can parse GEO data easy but OpenSearch/Elastic needs it in a specific format. ALWAYS FACTOR IN ALL DATA USE CASES!

Again, keep in mind overhead compute, troubleshooting, and whether you NEED to collect this data. Another important consideration to take (thanks to Brian for jogging this) is the concept of write-through caching. While Lambda is superfast, it's inefficient to continually query out OSINT for a specific domain or IP. Instead, consider writing to a cache such as Redis, Memcached, or using DynamoDB & DAX. You will attempt to GET (read) and write if it does not exist. 

Provided your Lambda is within a VPC and you have collocated caching infra (don't need to use managed services) or using PrivateLink it'll be a lot faster and lessen failure edge cases reading instead of continually querying a website.

Shoutout to IP API for a free, well-documented API and easy-to-use throttling indicators. All for now...

Stay Dangerous