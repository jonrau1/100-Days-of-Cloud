# 100 Days of Cloud Day 19

[Post Link](https://www.linkedin.com/feed/update/urn:li:share:6987551650915704832/)

## Post Contents

Day 19 of #100daysofcloud & #100daysofcybersecurity brings a rather involved Python script meant for batch processing of AWS WAF Logs that are sent directly to an S3 bucket, building off of Day 18.

AWS WAF Logs on their own are in JSON format, however, depending on where they are sent there are different things that will happen to that format. As we saw with DNS Firewall, sending JSON logs to CloudWatch Logs gets them packaged into another JSON object as a Base64-encoded, ZLIB-compressed mess that we need to pull apart with a bunch of different access tricks in Python and still get it formatted right.

AWS WAF to S3 is no exception. The most annoying part is that as AWS buffers and combines the Logs for you they write them in a GZipped JSON object (that's not the annoying part) - that are newline separated - as if it was a text document. CloudTrail on the other hand (we'll get to that one day) is in a nicer JSON object with a list called "Records" that you can loop nicely.

The other issues is that new-line separated JSON needs to be messed with some more, so we will Dump and Load JSON strings multiple times as the JSON is stringified. Within this script are a ton of tricks for dealing with stubborn JSON-ish objects as well as a few different ways to turn newline-sep logs into a Python list, and pop out any empty string as we use the split() function to do this list-transform.

We finish off with Reverse DNS lookups using our good friend Socket, and some basic GEOINT/OSINT enrichment we have been doing. To finish off, we use Pandas to slightly normalize the JSON and then have to jump through hoops to work JSON-to-DF-to-JSON-again magic. The nicest part of the script is there is not any I/O limitations as I show you how to read an S3 Object into memory instead of downloaded and opening it - it begs to be multiprocessed.

To kick off make sure you do Day 18 - the Prefix that is used to search can be modified depending on how you want to access your WAF Logs. Batch jobs like this are great for sampling logs (we use BLOCKs only here) for BI, ML, and rules tuning. We will turn out attention to real-time in the following days.

Stay Dangerous

#cloudsecurity #awssecurity #waf #netsec #aws #python 