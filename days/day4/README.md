# 100 Days of Cloud Day 4

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6982011824653099008/)

## Post Contents

Day 4 of #100daysofcloud & #100daysofcybersecurity, sticking with the theme of #SOAR playbooks, automation, and the thrice-cursed AWS "default" resources. As always, #GitHub in the links with the full code snippet and required permissions for it.

In Day's 2 and 3 we discussed the #Default #VPC and other bygone relics which AWS keeps around. Included within EVERY VPC is the Default Security Group (SG), which you cannot delete, so you need to get creative.

The Default SG has a rule which allows "full talk-to-self" that means anything that SG is attached to has unfettered network access across all ports & protocols. It is the opposite of least privilege, it is an anti-pattern at best and lets network-savvy attackers easily live off the land at worst.

To make the SG even worse, and really all SGs, is the default egress rule allows all outbound traffic. SGs are #stateful, which means that any connection opened is allowed in, so even if there is not a direct rule allowing access - if you or an #adversary opens a connection it can talk unfettered because of the egress. The only way to stop that is with a #Network #ACL - which are more trouble than they're worth - or using something like Network #Firewall, #DNS Firewall or an appliance with very specifically crafted rules.

A best practice is to NOT use that SG and blow all the rules away. Day 4's script lets you do that. However, I do not account for edge cases, it only deletes the DEFAULT RULES IT COMES WITH. It will add a tag telling people not to use it and will print out any extra rules. Security Hub and other CSPMs will tell you if anyone is USING it. The other issue is for #ClickOps that SG is chosen by default because...well...it's the default. So if you are not using IAC fervently, I bet you have a resource using it.

As always, #Responsive / #Destructive tech is controversial. Do not run this thing without making sure no one is using it. If they are, educate them, you can easily create & associate better SGs and THEN you can blow that shit to pieces.

As an industry we are rightfully concentrating on identity but network attack paths will continue to be a problem and it's an area that is often neglected too much. Blow away Default VPCs before this one to avoid extra work. When the VPC dies the Default SG dies. All for now...

Stay Dangerous

#cloudsecurity #awssecurity #aws #security 