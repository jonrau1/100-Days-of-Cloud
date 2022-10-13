# 100 Days of Cloud Day 6

[Post Link](https://www.linkedin.com/feed/update/urn:li:activity:6982403353934753792/)

## Post Contents

Day 6 of #100daysofcloud & #100daysofcybersecurity we're still on our network game. Meant to do this for Day 5, but regarding finding what resources use the Default SG can be done via #CSPM or #AWS Config - but let's do it the "hard way" - and it will prove a few points as well.

Financial considerations in security typically isn't broached outside of complaints about (lack of) budgets. That's valid, but not here. Despite being a "vendor #CISO" I'm very build-first. Outside of architecture and engineering chops a team needs are financial considerations - how to forecast usage/consumption and how it looks scaled up 2/5/10/20X for example. This is pertinent when it comes to AWS (and other #CSP) services since being regional it means needing to pay for it per-Region.

When it comes to a real cost-benefit analysis - is it worth to your team to run a $5/month bill up per every AWS Region when outside of your main region(s) it will just be an unnecessary discretionary cost. Why not whip up some scripts for #Detective Controls for things you want to find without needing to administer and pay for a multi-region deployment that has limited use.

That is where today's script comes in. Sure, you can throw on AWS Config & AWS Security Hub and write an Insight in SecHub to find resources using the default SG - but it's more money and work to just turn the services on before you see value. If you already know what you want, run a script: this script looks just at EC2, RDS and ALBs using Default SGs.

The second theme is around data consistency in your collection. Nearly every API has a different way it returns information, especially nested metadata. For security groups EC2 gives you a name, RDS has the ID and status, ALB just gives you IDs. You'll run into this a lot where every API you interface with needs its own parsing logic. You also need to ensure that you settle on what the data should look like - Pascal vs Camel Case, what you'll name the keys, if you maintain the API's naming or use your own, are you going to be further joining or enriching?

This script has an opinion. Normalized schema and pascal case, but you'll need to make the determination on your own. Recap: it's almost always more efficient to script your own detection, always be cognizant of costs, and settling on things as minor as schema and SLAs around your data collection leads to future #SecDataOps excellence.

Stay Dangerous

#awssecurity #cloudsecurity #security #bigdata