# 100 Days of Cloud Day 15

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6986021719715000320/)

## Post Contents

Day 15 of #100daysofcloud & #100daysofcybersecurity continuing with AWS WAF and IOC management. As a forewarning, using this script within your AWS account boundary will trigger a massive amount of GuardDuty findings, so maybe process it outside or set up a temporary exemption for a known clean & safe instance.

Day 15 is a modification of Day 14 but I removed the Rule Group & Web ACL creation to focus on IP Sets. I introduced logic that will check if a certain IP Set exits by name and contains logic to create it or update it. I also show you how to create multiple IP sets.

One of the IP Sets uses an IOC feed that contains Hostnames with logic to split it into a proper top-level domain and use our friend Socket to determine the IP address - which is where the learning comes in.

Firstly, there is a reason why cryptojacking and other domain-based IOCs are hard to react to, there are so damn many and they change so much just like IPs. While it may be higher on the Pyramid of Pain it's only just so. When the mining pool lies dormant there may not be any record either so trying to find the IPs from them is hard. Goes to show you another reason to have layered & redundant defenses but attempting to stop activity and going with an Allowlist-oriented egress versus stopping individual IOCs is MUCH MORE VALUABLE (but harder).

Another point this brings up is IOC management. Many open source lists are not updated anymore, or if they are, they do not age out IOCs. Aging of IOCs is a hot topic. You can argue you only want what is known to be active, others argue to keep them all because attackers change up, some argue not to use them at all.

This script will take almost 20 minutes to run on a decent machine, since you're looking at each hostname (even with logic to skip past any you've seen), turning them into domains and finding the IP. Most fail. I got 3226 IPs from 1000s of active domains out of 10s of 1000s of hostnames.

You should strongly consider a dedicated CTI platform that can perform management of IOCs for you. MISP is the best open source bet but you still need to have a datastore that can accept TTLs (to age out records) and you'll need to perform parsing to determine if an IP is legit (i.e. not a private IP), dedupe and other things.

That doesn't factor in compute/storage costs, human capital of building an IOC #SecDataOps system, and having yet another pipeline to maintain. Then there are false positives and also understanding your precise threat environment. Is cryptojacking even a valid threat to you if you only use ALBs, APIGW, and Lambda?

It'll be faster for WAF and other #netsec automation - if you use IOCs - to work from a central place and set a cap on IP Sets. 10K CIDRs get consumed very quickly. For IOCs I recommend harvesting them yourself using honeypots...which we may get into in a few weeks.

Stay Dangerous

#waf #cloudsecurity #awssecurity #ioc #cti #threatintelligence #bigdata #aws