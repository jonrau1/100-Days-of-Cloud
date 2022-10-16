import os
import boto3
import gzip
import json
import socket
import urllib3
from time import sleep
import pandas as pd

WAF_LOG_S3_BUCKET = os.environ['WAF_LOG_S3_BUCKET']
# export WAF_LOG_S3_BUCKET='aws-waf-logs-BLAHBLAHBALH'

sts = boto3.client('sts')
AWS_ACCOUNT_ID = sts.get_caller_identity()['Account']
AWS_REGION = boto3.Session().region_name
del sts

def iterate_log_s3_objects():
    '''
    Iterates over a specific AWSLogs prefix within S3 to retrieve AWS WAF Logs and provides them 
    to the `log_parser_commander()` function
    '''
    s3 = boto3.client('s3')

    # Create the search prefix, the format is as follows
    # BUCKET_NAME/AWSLogs/ACCOUNT_NUMBER/WAFLogs/REGION_NAME/WEB_ACL_NAME/YYYY/MM/DD/hh/mm
    # the minute partitions are done every 5 minutes where there is activity such as 20/ 25/ 30/ 35/ 40/
    searchPrefix = f'AWSLogs/{AWS_ACCOUNT_ID}/WAFLogs/{AWS_REGION}/'

    # Empty list to contain all in-scope S3 Keys to be returned
    s3Keys = []

    # S3 Paginator and Iterators
    paginator = s3.get_paginator('list_objects_v2')
    iterator = paginator.paginate(
        Bucket=WAF_LOG_S3_BUCKET,
        Prefix=searchPrefix
    )
    # Begin the Loop
    for page in iterator:
        for o in page['Contents']:
            s3Keys.append(str(o['Key']))

    return s3Keys

def log_parser_commander():
    '''
    This function receives a list of S3 key names from `iterate_log_s3_objects()` and 
    sends them to `process_s3_log_object()`
    '''
    # Empty list of processed logs
    processedLogs = []

    for key in iterate_log_s3_objects():
        # We have to dump the JSON object we get into a String and reload it into JSON with loads
        jsonLog = json.loads(
            json.dumps(
                process_s3_log_object(key)
            )
        )
        # since we are dealing with lines that we turned into a list we need to loop it
        for line in jsonLog:
            # we also need to load the individual lines into a JSON object to access
            jsonLine = json.loads(line)
            # if there is not a BLOCK Action, we will ignore
            if jsonLine['action'] != 'BLOCK':
                continue
            else:
                # now we can process the log
                processedLogs.append(enrich_waf_log(jsonLine))

    # Write the a file
    with open('./enriched_waf_block_logs.json', 'w') as jsonfile:
        json.dump(
            processedLogs,
            jsonfile,
            indent=4,
            default=4
        )

def process_s3_log_object(key):
    '''
    Pulls S3 object information into memory and processes it
    '''
    s3 = boto3.resource('s3')

    # Supply the key name and read the S3 Object into memory with an S3 Resource
    obj = s3.Object(
        WAF_LOG_S3_BUCKET,
        key
    )
    # WAF Logs are GZipped JSON - the context manager reads the object out using S3 Resource Actions e.g., get()
    with gzip.GzipFile(fileobj=obj.get()['Body']) as gzipfile:
        # Decode the file
        content = gzipfile.read().decode()
        # WAF LOGS ARE STUPID! As they are buffered into S3 they are added one after another similar to a text file
        # however, we cannot use readlines() so we must conditionally split by a newline (\n)
        logList = content.split('\n')
        # when we do that, since there is technically a newline after even the single log entries, we need to detect if their is an empty string ('')
        # as split() will always turn into a list we can use remove() after checking if its there
        if '' in logList:
            logList.remove('')

    return logList

def enrich_waf_log(waf_log):
    '''
    Enriches and flattens specific elements of the WAF log
    '''
    # Pool manager for urllib3
    http = urllib3.PoolManager()

    # Parse out the ClientIP from the log
    clientIp = waf_log['httpRequest']['clientIp']

    # Attempt a Reverse DNS Lookup - socket's "getnameinfo" expects a tuple of an IP and a port
    # we will just try to use plain HTTP as to not mess with any HTTPS or weird stuff...
    addr = (clientIp, 80)
    try:
        # Response is a Tuple, access the first value with [0]
        hostname = socket.getnameinfo(addr, 0)[0]
        # Sometimes you get the IP back, that's not exactly a hostname...
        if hostname == clientIp:
            hostname = None
    except socket.error:
        hostname = None

    # Now let's try to get some sense of where exactly these adversary turds are coming from
    # Generate request url for use
    url = f'http://ip-api.com/json/{clientIp}?fields=status,message,lat,lon,isp,org,as,asname'
    # GET request
    r = http.request(
        'GET',
        url
    )
    ttlHeader = int(r.headers['X-Ttl'])
    requestsLeftHeader = int(r.headers['X-Rl'])
    # handle throttling
    if requestsLeftHeader == 0:
        ttlHeader = int(r.headers['X-Ttl'])
        waitTime = ttlHeader + 1
        sleep(waitTime)
        print('Request limit breached - retrying')
        del r
        # new request
        r = http.request(
            'GET',
            url
        )
        ipJson = json.loads(r.data.decode('utf-8'))
        latitude = float(ipJson['lat'])
        longitude = float(ipJson['lon'])
        isp = str(ipJson['isp'])
        org = str(ipJson['org'])
        asn = str(ipJson['as'])
        asnName = str(ipJson['asname'])
    # If not fail
    else:
        ipJson = json.loads(r.data.decode('utf-8'))
        latitude = float(ipJson['lat'])
        longitude = float(ipJson['lon'])
        isp = str(ipJson['isp'])
        org = str(ipJson['org'])
        asn = str(ipJson['as'])
        asnName = str(ipJson['asname'])

    # We will insert the new values following the camelCase WAF Log pattern back into the "httpRequest" dict
    waf_log['httpRequest']['hostname'] = hostname
    waf_log['httpRequest']['latitude'] = latitude
    waf_log['httpRequest']['longitude'] = longitude
    waf_log['httpRequest']['isp'] = isp
    waf_log['httpRequest']['org'] = org
    waf_log['httpRequest']['asn'] = asn
    waf_log['httpRequest']['asnName'] = asnName
    
    # Use Pandas to slightly flatten and normalize the JSON
    df = pd.json_normalize(waf_log)
    # We cannot work with a DataFrame, so dump it back into a JSON object using DataFrame.to_json()
    jsonLog = json.loads(df.to_json(orient='table', index=False))
    # When using "table" orientation (and others) going from a DataFrame to JSON, it will add the schema at a top level list
    # and then the actual data is under Data - but it will also wrap the log lines into another List - so we need to get the first
    # object from the "data" list in the converted DF...
    return jsonLog['data'][0]

log_parser_commander()