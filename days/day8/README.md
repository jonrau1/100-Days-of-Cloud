# 100 Days of Cloud Day 8

[Post Link](https://www.linkedin.com/posts/activity-6983548500927991808-V53v?utm_source=share&utm_medium=member_desktop)

## Post Contents

Day 8 of #100daysofcloud and #100daysofcybersecurity still on networking but moving to DNS-related controls. We will stay with this theme for 2-4 more days depending on what I can think of.

As always, code snippets & IAM permissions within linked GitHub in comments.

A few years back AWS released Route 53 Resolver DNS Firewall (DNSFW) which transparently attaches to the default Resolver associated with each VPC. This gives the ability to inspect DNS requests transiting your entire VPC with up to 100K domains. You can set rules to Count, Block or Allow giving you the ability to create incredibly restrictive DNS egress zones or block/alert on known domain IOCs.

AWS manages Domain Lists using threat intel from AWS, Crowdstrike and ProofPoint (same as GuardDuty, essentially) which keeps track of known malware C2, botnets and miner pools. So for every GuardDuty DNS-related alert you can likely use DNSFW as a Preventative control - and we will be looking into a real-time SOAR use case for that later on!

DNSFW works by creating a Rule Group (which is essentially the firewall) which stores Rules which are made up of a Domain List (which hold, domains, shockingly!) and a Priority and Action. For Block action you can customize the DNS response to your liking such as returning No Data or NXDOMAIN. You can craft your own Domain Lists up to 100K as mentioned. DNSFW is easy to associate, it does not require mutating route tables and routes like Network Firewall does. Making it akin to WAFv2 which is nice.

Logging is handled by the Resolver Query Logging - we will cover that tomorrow as well as streaming and processing the data in Lambda with some basic alerting!

DNSFW does get expensive if you have very chatty applications - I know for a fact that a self-hosted MongoDB Atlas is super chatty - found that out the hard way at IHSM when I ran up someone's account several 10s of 1000s of dollars. Whoops. At the very least I still do think it's worth attaching a managed Domain List and seeing if you have alerts in a VPC used by your production apps.

The script is single-Region and will create a very basic DNSFW using the Malware-domains managed Domain List. It sets the Action to Count and associates with your VPCs. Feel free to expand it as needed, everything has a function along with a way to create a unique request ID with the `uuid` module in Python.

All for now...Stay Dangerous

#dnssecurity #awssecurity #cloudsecurity #netops #networksecurity #netsec #infosec #cloud #aws 