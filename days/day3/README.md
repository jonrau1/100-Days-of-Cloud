# 100 Days of Cloud Day 3

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6981629745717215233/)

## Post Contents

It is Day 3 of #100daysofcloud & #100daysofcybersecurity and I have a spicy one for you that builds on Day 2 *AND* I have a GitHub that will keep the full code snippets, Carbon screenshots, and the post for posterity. More reason to engage here so we can extrapolate, exchange ideas, and give you a reason to look back.

The post & code will be mirrored after each post. Link will always be in the comments as to not anger the algorithm. I do this so people can see & learn not to stoke some bullshit impressions ego.

Day 3 has the extended script which teaches us how to separate discrete units of logics in our Python scripts into functions and call them from a main script. We are also making our first #SOAR (Security Orchestration & Automated Response) #playbook for sorts.

Focusing on the latter, SOAR is a muddy, multi-disciplinary space that describes any tool or "thing" which automates some security tasks for use and/or orchestrates it on our behalf. This can be a workflow tool that will automatically response to a given input - such as responding to a Splunk alert and sending alerts to PagerDuty, it can be a #CNAPP that generates an IAM Permissions Boundary for you, or a tool that will destroy instances spawned by a known malicious actor. You can use anything for SOAR, and in my experience, you're 99% better of BUILDING it yourself.

That said, SOAR is a contentious topic. You need a lot of Delete/Update/Describe/List permissions and if an adversary gained control of this SOAR #identity, bad things can happen. Also, product teams and your security organization may dislike of you having orbital nukes to crush their non-compliant resources. There is always the risk you delete something legit or have a runaway SOAR workflow that eats itself (I've seen that before). Before doing this you should weigh all the pros & cons and honestly without GREAT #Detection, using #Responsive #Controls is not good enough. All opt for Preventative measures AND #EDUCATE & #EMPOWER YOUR PARTNERS!!

On the #Python side, this script has functions which carry out specific tasks passed on an input. In our case we have a function for yeeting IGWs and another for Subnets. This helps keep your code clean, helps with debugging, looks cool as hell, and can improve performance for not needing to use a lot of try/except and for-loops within a big ass code monolith. You can go even further with defining Classes and calling your Python scripts like legit modules such as Boto3 and Pandas, but we'll do that...later?

Anyway, IAM Permissions needed are in GitHub too. If you do setup SOAR identities best practice is to control the trust boundary with who/what can use it. Minimum necessary permissions - try to keep identities per a playbook if you can (for destructive ones) - and maybe even use IP/network conditions (VPC, VPCE, SourceIp) and MFA.

Seriously though, destroy the Default VPCs, they are nothing but a free persistence & defense evasion area for adversaries.

Stay Dangerous