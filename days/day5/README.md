# 100 Days of Cloud Day 5

[Post Link](https://www.linkedin.com/feed/update/urn:li:activity:6982403353934753792/)

## Post Contents

Day 5 of #100daysofcloud & #100daysofcybersecurity. No code today, Giants football is on and I got some #steakposting to get to later. Will back this up to GitHub tomorrow but there will not be any snippets, just theory today.

Sticking with the #network #security concepts for the next few days on AWS, going to cover off some other tools. I get that identity is overwhelmingly the largest vector of initial access, but not every compromised identity is a true admin, I'm sure the adversaries would love that. That is why they laterally move. That is why cryptojacking is such a boring attack. That is why data exfiltration is simple for #ransomware gangs and #doublextortion is a thing.

While paring down egress for Security Groups will be really hard to do for your edge, there are other tools you can add in for a hardened network edge. Firstly, for private security groups, write your SGs per layer of your app - be it Private Lambda, EC2s running a webapp, EKS Nodes, etc. You can reference the other SG you know incoming traffic will be instead of allowing an entire Subnet or VPC CIDR.

Application Load Balancers have some built in security settings such as overriding WAF Fail Open in case WAF ever falls down, ALB will not allow the uninspected traffic through. That is a tradeoff of availability for confidentiality and I do not know anyone who does that. HTTP Desync Attack protection helps mitigate HTTP request smuggling, and you can also drop invalid HTTP headers. You should also turn on access logging, it is in a weird CEF-like format, but Athena has a way to parse it.

Next up is AWS WAF. Web App Firewalls protect against web app attacks - if you do not know how to write the rules (AWS does make it easy) you can use the managed rule groups to counter known bad IPs, SQLI, XSS, CSRF, specific parts of the request, and more. While there are ways around some of the protections, like very large requests, with some of the more advanced features like CAPTCHA challenges and bot protection. The logs are easy to parse and can be moved with Firehose (and converted to Parquet) and you can even do some fun NSPM/ML work with it (that's for later). You can orchestrate across your Organization use FMS as well, even auto-attaching.

Next is CloudFront. Not a security tool on its own but CDNs help absorb DDOS (along with Shield), great log source, but with Lambda@Edge you can intercept requests and do some really interesting things dropping suspect requests that look like XSS by enforcing to setting certain headers. We'll do a Day on this soon.

Network Firewall is a stateful NGFW-ish tool, it's operates like a Gateway, and works a lot like Suricata IDS/IPS to. You can create fine-grained rules to inspect the request and drop traffic that doesn't match specific ports/protocols and IPs. You can write Suricata-type rules for deep inspection and it also supports FMS and AWS Managed Threat Lists. Great for ingress/egress centralization.

Stay Dangerous