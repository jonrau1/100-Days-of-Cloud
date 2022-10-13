# 100 Days of Cloud Day 7

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6983067365072650240/)

## Post Contents

Day 7 of #100daysofcloud & #100daysofcybersecurity, one week in already, time flies when you're having fun. As always - GitHub containing the code, IAM permissions, post contents and even a backup of the Carbon screenshot in the comments. Got some feedback on the formatting and I'll refactor it...eventually.

Continuing to stick with the networking angle and the almighty Security Group as it pertains to Attack Surface Management (ASM). #ASM is a simple discipline/tasking with a lot of takes on how its done. The simplest way to get started requires a good asset management program - using managed tools or your own scripts - like we have been doing and working backwards from what is internet-facing.

You will always have a surface, except in exigent cirucmstances depending on industry, especially if you run a SaaS app, self-manage enterprise services (mail servers, CDNs, etc.) or maybe use bastions. There are plenty of legitimate reasons and on its own it is never an issue until it is: new 0-Day drops, new exploit TTPs, new vulns, silly misconfiguration, AppSec issue found. With ASM you want to interdict these potential problems and continuously monitor them.

CSPM has gotten us laser focused on the infra-side configurations, but things like IMDSv2, Enclaves, EBS Encryption, etc. is not a problem until it becomes one due to a network/identity-based attack first. It's not that it is unimportant but with limited resources - always start where your biggest impacts (and biggest threats) lay.

The script provided builds on similar concepts we've touched on already: saving files, using multiple Python functions, trying to introduce logic to disqualify non-pertinent resources to lower our compute overhead. I also threw in some other fun tricks like conditionally turning lists to comma-separated strings.

We will use the Python3 wrapper to Network Mapper (#NMAP) and NMAP itself, the ubiqituous NetOps/OffSec/SecOps workhorse tool. I see it make all sorts of "Top 10 Tools to X" lists, here is how to use it. We will only be performing IPv4 TCP scans as that covers most use cases. If you're wanting ICMP or UDP or IPv6 you need to modify this.

You'll find all public EC2s, determine the address (using Socket if it only has a hostname...somehow), statically analyze the SG for open TCP rules, and feed the info to NMAP to run a port scan without host discovery. Then you get a small JSON file you can work backwards from for reporting.

To close ASM is not just EXTERNAL. While that's the easiest thing for adversaries to hit, lateral movement risks are harder to stomp out. Performing internal ASM tasks is great for governance and making sure minimum necessary network permissibility and proper segmentation is in effect. Don't be that guy/gal letting your teams run roughshod with permitting all manners of traffic across trust boundaries in your VPCs/VPNs/Direct Connects. That'll get ya killed in these mean cyber streets. All for now...

Stay Dangerous

#awssecurity