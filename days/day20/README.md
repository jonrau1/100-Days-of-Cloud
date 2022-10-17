# 100 Days of Cloud Day 20

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6987839653370290177/)

## Post Contents

Day 20 of #100daysofcloud & #100daysofcybersecurity focusing on WAF Logs yet again, but on near real-time processing, versus batch processing ad hoc.

In terms of your overall #SecDataOps journey, you'll end up using both streaming (real/near-real time) and batch workloads), especially when it comes to collecting 100% of whatever data your interested in. Outside of green-fields use cases, you likely have X amount of Months/Years/Petabytes of data you need to sift through from a certain point as well as collecting whatever that is.

There are different reasons to want to do so, but I find myself combining both batch & streaming a lot especially if there is a chance I can lose my data and want to fill in any blanks. A lot of that also depends on the downstream datastore - but we will extrapolate on that a lot later.

Today's logic is using a Lambda function triggered off of S3 Events. You may raise your eyebrow at the fact we are kicking off a streaming / near real-time data job using event-driven architecture from....a bucket...and I do agree. This use case is better driven directly off of CloudWatch Logs or at least needs a modification to delete the original objects in the bucket as you'll suddenly have the OG copy and another copy that is enriched elsewhere.

The fact is, S3 is not the best place to put these, and despite Athena Engine 3 coming out - that service is still super expensive as will be Glue when you continue to crawl it multiple times. There is no in-between with Glue - you either crawl an entire bucket, a very specific path, or you crawl any new objects. If you'll be using real-time logs like from WAF you are probably putting it into a SIEM for post-hoc analysis, into a better performant data lake (after chopping the logs to pieces you care about), and likely not using S3 directly.

It really comes down to the what the end-state and goal is. If it's part of threat hunting you want it as fast as possible with meaningful metadata - so that makes sense to get ALLOWS / COUNTS and only grab information about the client. If you want to review what you blocked, it makes sense to do batch jobs, if you want to use it as part of the OPS equation of your SecDataOps/DevSecOps - then it makes sense to grab everything and compare it to APM and clickstream data.

All for now...

Stay Dangerous

#python #cloudsecurity #awssecurity #aws