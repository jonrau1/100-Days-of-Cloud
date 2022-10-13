# 100 Days of Cloud Day 13

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6985295125828485120/)

## Post Contents

Day 13 of #100daysofcloud & #100daysofcybersecurity taking a step back from the specifics of AWS #netsec tools and #logging to approach write-through caching.

In Day 12 I mentioned using tech such as DynamoDB or Redis as a write-through cache. A cache is any datastore that temporarily holds data to be retrieved and used later. That's a vast oversimplification, but caching is important for any setting which you will be frequently accessing specific data from a datastore that wouldn't be able to otherwise handle the request rate.

At least that's the "science" behind it, the "art" is balancing the scales of adding yet-another-technology to your stack and figuring out if you'll knockoff whatever is downstream if you keep querying it for whatever data it is.

As a #SecDataOps engineer learning caching tech, implementation and the decision trees behind it is important. When it comes to just-in-time enrichment it makes a lot of sense to use a cache. Whether it's because you're enriched in real-time before you deliver the data or it's ad-hoc as part of an IR Playbook or a SIEM rule that ingests IOCs or other enrichment it's probably much better to pull it from a cache. That goes doubly for real-time processing where you may run into throttling from a 3rd party API due to a high event-per-second rate like you can get from security/network logs in even a small environment.

I take the enrichment use cases from Days 11 and 12 and put it into a basic Python script and have an opinionated way of using a function to get if a value exists in DynamoDB. If it does not exist, you query IP API as usual and then write to DyanmoDB for subsequent calls. In my testing, if the values are cached, it saves you 5-10ms per item you query. That is with a Gateway Endpoint.

There are some other goodies in their like converting Floats to Decimals, creating Time-to-live values, and such. I include a bash script to create the table to match the script. DynamoDB expert-level topics may be covered later, there is a ton of great stuff you can do with DynamoDB to tune access patterns, improve efficiency, stream data, and more. I love it and it's my go-to datastore along with S3 for 95% of things I do.

Final note: Hostname/Domain -> IP isn't always 1:1. If a domain is a fronted by a CDN like Fastly, CloudFront or CloudFlare you'll have 10s if not 100s of possible IPs. So the table design only accounts for IPs not for their paired hostnames. Keys in DynamoDB enforce uniqueness and access. If I set a RANGE key of Hostname in addition to the HASH key of IP, you'd need to query and write with both. 

No permissions are included, don't want to give all the answers, you won't learn anything.

Stay Dangerous 

#threatintelligence #bigdata #aws #cloudsecurity #awssecurity 