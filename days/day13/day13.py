import os
import socket
import urllib3
import json
from decimal import Decimal
from time import sleep
import boto3
import botocore.exceptions
from datetime import datetime
# Env vars
IP_GEOINT_CACHE_TABLE_NAME = os.environ['IP_GEOINT_CACHE_TABLE_NAME'] # export IP_GEOINT_CACHE_TABLE_NAME='dyanmodb_table_here'
EPOCH_DAY = 86400

# Pool Manager for urllib3 to (re)use
http = urllib3.PoolManager()

# Scary people to find
SOME_HACKERS_I_GUESS = [
    'thehackernews.com',
    'krebsonsecurity.com',
    'csoonline.com',
    'darkreading.com',
    'threatpost.com',
    'welivesecurity.com',
    'www.infosecurity-magazine.com',
    'www.bleepingcomputer.com'
]

# Boto3 Clients
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(IP_GEOINT_CACHE_TABLE_NAME)

def determine_ip_address(hostnames):
    '''
    Uses Socket to find the IP address for a given hostname
    '''
    enrichedHostnames = []
    for hostname in hostnames:
        try:
            ip = socket.gethostbyname(hostname)
        except Exception as e:
            print(e)
            ip = None

        if ip != None:
            # Get cached results
            geoint = get_cached_geo_intelligence(ip)
            # If there are not cached results, write fresh
            if geoint == None:
                print(f'No cached results found for {ip}!')
                geoint = geo_intelligence(ip)
            countryCode = geoint['CountryCode']
            latitude = float(geoint['Latitude'])
            longitude = float(geoint['Longitude'])
            isp = geoint['Isp']
            org = geoint['Org']
            asn = geoint['Asn']
            asnName = geoint['AsnName']
        else:
            countryCode = None
            latitude = int(0)
            longitude = int(0)
            isp = None
            org = None
            asn = None
            asnName = None

        enrichedHostname = {
            'Hostname': hostname,
            'IpAddress': ip,
            'CountryCode': countryCode,
            'Latitude': latitude,
            'Longitude': longitude,
            'Isp': isp,
            'Org': org,
            'Asn': asn,
            'AsnName': asnName
        }
        if enrichedHostname not in enrichedHostnames:
            enrichedHostnames.append(enrichedHostname)

    save_data_to_file(enrichedHostnames)

def get_cached_geo_intelligence(ip):
    '''
    Attempts to find cached geoint results for a given hostname
    '''
    try:
        r = table.get_item(
            Key={
                'IpAddress': ip
            }
        )
        if 'Item' in r:
            geoint = {
                'CountryCode': r['Item']['CountryCode'],
                'Latitude': float(r['Item']['Latitude']),
                'Longitude': float(r['Item']['Longitude']),
                'Isp': r['Item']['Isp'],
                'Org': r['Item']['Org'],
                'Asn': r['Item']['Asn'],
                'AsnName': r['Item']['AsnName']
            }
        else:
            geoint = None
    except botocore.exceptions.ClientError as error:
        raise error

    return geoint

def geo_intelligence(ip):
    # Generate request url for use
    url = f'http://ip-api.com/json/{ip}?fields=status,message,countryCode,lat,lon,isp,org,as,asname'
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
        countryCode = str(ipJson['countryCode'])
        latitude = float(ipJson['lat'])
        longitude = float(ipJson['lon'])
        isp = str(ipJson['isp'])
        org = str(ipJson['org'])
        asn = str(ipJson['as'])
        asnName = str(ipJson['asname'])
    # If not fail
    else:
        ipJson = json.loads(r.data.decode('utf-8'))
        countryCode = str(ipJson['countryCode'])
        latitude = float(ipJson['lat'])
        longitude = float(ipJson['lon'])
        isp = str(ipJson['isp'])
        org = str(ipJson['org'])
        asn = str(ipJson['as'])
        asnName = str(ipJson['asname'])

    # create ttl and insert into the Dict
    tstamp = int(datetime.utcnow().timestamp())
    oneWeek = 7 * EPOCH_DAY
    ttl = tstamp + oneWeek

    geoint = {
        'IpAddress': ip,
        'CountryCode': countryCode,
        'Latitude': latitude,
        'Longitude': longitude,
        'Isp': isp,
        'Org': org,
        'Asn': asn,
        'AsnName': asnName,
        'Ttl': ttl
    }
    try:
        # Write Floats as Decimals...
        table.put_item(
            Item=json.loads(
                json.dumps(
                    geoint
                ), 
                parse_float=Decimal
            )
        )
    except botocore.exceptions.ClientError as error:
        print(error)
        print('Failed to write results to DynamoDB')

    return geoint

def save_data_to_file(enriched_hostnames):
    '''
    Writes enriched hostnames to JSON file
    '''

    with open('./enriched_hostnames_list.json', 'w') as jsonfile:
        json.dump(
            enriched_hostnames,
            jsonfile,
            default=str,
            indent=2
        )

determine_ip_address(
    hostnames=SOME_HACKERS_I_GUESS
)