# 100 Days of Cloud Day 14

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6985658695674118145)

## Post Contents

Day 14 (holy crap it's been 2 weeks!?) of #100daysofcloud & #100daysofcybersecurity continuing to work our way down the AWS #netsec services with #WAF.

The current incarnation of AWS WAF is actually a much needed V2 that greatly expanded offerings with things as crazy as custom responses, header injection, CAPTCHA challenges, managed rule groups w/ versioning support, Bot Control, distributed logging, and new supported targets (Cognito & AppSync).

Like other WAFs, AWS WAF is a Layer 7 application level firewall that intercepts and inspects requests sent to it and determines what to do with the request, that's the simple answer.

The core of WAF is the Web Access Control List (Web ACL/WACL). The WACL is made up of one or more Rule Groups which can be Managed (provided by AWS & Partners) or Custom. Custom Rule Groups are made up of Rules you write/create with the engine which can pick apart anything from the URI, Headers, Body, and more to match against specific conditions such as IOCs in an IP Set, custom regex in a Regex Pattern Set, SQL Injection, XSS, or Rate-based Rules.

The Rules specify the Actions you want to take, you can return Custom Responses (HTTP 418 FTW lol), you can issue a CAPTCHA Challenge, and you can control fine-grained metrics monitoring & logging per Rule as well at the Rule Group level. You can override specific Rules/Rule Groups in the WACL and set more logging at that level.

For automation folks out there, you can orchestrate creation and assignment of WACLs using AWS Firewall Manager Service (which relies on AWS Config) or write it yourself. It is a decently large uplift from a #SecDataOps perspective to continuously inventory supported targets, update your rules, tune them, override, and more but it can be done.

Today's script is Step 0 for that and introduces some fun #Python tricks for conditional formating, downloading text files, turning text to a List, validating IOCs and ensuring Lists stay a certain size. We also look at the botocore exceptions library to gracefully deal with errors.

The Web ACL created will only contain an IP Set of the latest 10K IP IOCs from CINS Score and has user-agent based rules to block bastards using Nimbostratus and Masscan. I show you how to do ARN-references and set custom responses and visibility settings.

I'll spend a few more days expanding this, who knows, you may decide to use it for yourself!

Stay Dangerous

#waf #cloudsecurity #awssecurity #automation #firewall #network 