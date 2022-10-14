# 100 Days of Cloud Day 17

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6986785181017763840/)

## Post Contents

Day 17 of #100daysofcloud & #100daysofcybersecurity finalizes the AWS WAFv2 (Regional) creation script. This is pretty close to what we're using to deploy out WAFs - with a lack of a #SecDataOps pipelines to grab IOCs and FMS - if you care about if this is used for real.

This is a modification over the last few days which now has conditional creation/updating similar to an IAC tool will have. So instead of the script dying to attempting to provide you back an ARN it will refresh every piece of the WAF infrastructure stack.

The only better way to do this using AWS Firewall Manager (FMS) which we will be covering soon as well. That said, FMS is reliant heavily on AWS Config, which can get expensive and cumbersome to deploy (which I also have a fix for). There are also ways to do it without FMS.

I get that the WAF as a be-all-end-all preventative network security control is pretty silly to rely on like we're in 2014 again, but, it still has its place especially when it's as easy to configure, deploy and is very affordable like AWS WAFv2. With all of the goodies built into it, I would seriously raise an eyebrow at a security team who didn't want to put it in front of their SaaS application.

We will get into logging considerations next, I really like the WAFv2 logging format, though it does contain a lot of dynamic nested schema elements which only appear in certain cases. Not efficient for transforming every record but we will get into that.

Nothing much else to say here, by this juncture you should be rather well versed in creating Python functions and dynamically using them as situations arise. While you *could* do this with Infrastructure-as-Code I find creating the IP Sets at least and any custom rules is pretty annoying in YAML or some nested-escaped-bullshit Terraform. Do whatever works for you.

Stay Dangerous.

#security #networksecurity #cloudsecurity #awssecurity