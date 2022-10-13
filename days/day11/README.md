# 100 Days of Cloud Day 11

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6984565708814745600/)

## Post Contents

Happy Saturday, Day 11 of #100daysofcloud & #100daysofcybersecurity brings us more parsing goodness with some VERY BASIC enrichment of our DNSFW Query Logs. GitHub in the comments, added a table of contents to it for you.

Today's Lambda function code is a modification of Day 10 that adds even more simplification to the function and introduces a new helper function to conduct enrichment. The topic of enrichment like anything is security is subjective, and before you (as a #SecDataOps or #Detection Engineer) decide to throw a ton of extra work - you must ask yourself "What" and "So What".

Having things like geolocation data, hostnames/IPs/domains, WHOIS, Shodan/Censys/Graylog, and other sort of information may not be pertinent to you. There is *always* a cost to enrichment - even if you are as optimized as possible - there's extra compute overhead, extra time (which may lead to an SLA breach), and more things that can break in your pipeline.

You shake these things out by figuring out downstream use cases, if you can afford to do w/o that data, can you afford to lose ALL data because you're missing the enrichment, and does anyone really care for it?

Another important data tenant is governance - it's too large to get into here but decided on schema ahead of time for things as predictable as cloud API results and log formats will save you a lot of effort. Do you want to stick with default fields or change to Pascal Case? Do you want nested objects or make them strings? Should you rename a field from source? Do you need all fields?

This script takes an opinion here on all of the above: adding extra field, using PascalCase, stringifying lists, and renaming some fields. See if you can find it all. The function doesn't send the data anymore - you can figure that out yourself. Today we use the `Socket` module to determine the IP from the queried domain. While your DNSFW may BLOCK/COUNT it what about your other firewalls (WAFs, NGFWs), EDR tools or AWS GuardDuty? Maybe having an IP is useful especially when hackers bamboozle you with a new DGA.

Tomorrow we will add A LOT more enrichment just to show you. Fun fact, this function is more efficient than yesterday's. Average memory used is 39MB versus 55MB and average time is about the same 10-65MS depending how many logs you get at once.

Stay Dangerous

#cloudsecurity #awssecurity #aws #cloud 