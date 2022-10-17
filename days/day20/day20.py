import boto3
import gzip
import json
import socket
import urllib3
from time import sleep

def lambda_handler(event, context):
    objects_parser(event['Records'])

def objects_parser(records):
    '''
    Receives list of S3 Events from Handler, processes the Bucket & Key Name and sends to another function
    '''
    # Empty list of processed logs
    processedLogs = []
    # Process events from handler
    for record in records:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        # Pass the bucket & key to the processor and receive a list of JSON logs back
        # We have to dump the JSON object we get into a String and reload it into JSON with loads
        jsonLog = json.loads(
            json.dumps(
                process_s3_log_object(bucket, key)
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
    
    if processedLogs:
        log_forwarder(processedLogs)

def process_s3_log_object(bucket, key):
    '''
    Receives the Bucket & Key Name from `objects_parser()`, downloads the corresponding object, and transforms to JSON
    '''
    s3 = boto3.resource('s3')

    # Supply the key name and read the S3 Object into memory with an S3 Resource
    obj = s3.Object(
        bucket,
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
    Enriches specific elements of the WAF log received from `objects_parser()`
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

    return waf_log

def log_forwarder(processed_logs):
    '''
    Receives a list of processed logs from `objects_parser()` and sends them places
    '''
    for log in processed_logs:
        print(log)

    # TODO : Implement ways to send to SNS / SQS / Kinesis...