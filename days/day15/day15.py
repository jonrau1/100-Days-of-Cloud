import urllib3
import boto3
import socket
import ipaddress
import botocore.exceptions
from datetime import datetime
from time import sleep

wafv2 = boto3.client('wafv2')

CINSSCORE_URL = 'http://cinsscore.com/list/ci-badguys.txt'
CINSSCORE_FILE_NAME = './ci_badguys.txt'
COINBLOCKER_URL = 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt'
COINBLOCKER_FILE_NAME = './coinblockerlist.txt'
CINSSCORE_IPSET_NAME = '100DaysOfCloud-CINS'
COINBLOCKER_IPSET_NAME = '100DaysOfCloud-COINBLOCKER'

def download_ioc_feeds():
    '''
    Downloads and saves various IOC feeds to file
    '''
    # Pool Manager for urllib3
    http = urllib3.PoolManager()
    # CINSSCORE
    try:
        # GET request
        r = http.request(
            'GET',
            CINSSCORE_URL
        )

        with open(CINSSCORE_FILE_NAME, 'wb') as file:
            file.write(r.data)

        r.release_conn()
        del r

        print(f'Wrote CINS Score IOC feed to file.')
    except Exception as e:
        raise e

    # COINBLOCKER
    try:
        # GET request
        r = http.request(
            'GET',
            COINBLOCKER_URL
        )

        with open(COINBLOCKER_FILE_NAME, 'wb') as file:
            file.write(r.data)

        r.release_conn()
        del r

        print(f'Wrote CINS Score IOC feed to file.')
    except Exception as e:
        raise e

    del http

    return True

def parse_cinsscore():
    '''
    Reads out the CINS Score IOC file and parses the first 10K IOCs
    '''
    # Empty list for new IOCs
    cinscoreIocs = []
    
    # Readout the file and close it
    cinsscoreIocFile = open(CINSSCORE_FILE_NAME, 'r')
    cinsscoreIocList = cinsscoreIocFile.readlines()
    cinsscoreIocFile.close()

    # Parse the list and strip the newline
    for ioc in cinsscoreIocList:
        # IP Sets accept up to 10K values, stop there
        if len(cinscoreIocs) < 10000:
            try:
                ioc = ioc.replace('\n','')
                # Check to ensure the IP Address is good...
                ipaddress.ip_address(ioc)
                # Write into the list as a CIDR
                if ioc not in cinscoreIocs:
                    cinscoreIocs.append(f'{ioc}/32')
                else:
                    continue
            except ValueError:
                print(f'{ioc} is invalid!')
                continue
        else:
            break

    print(f'Parsed {len(cinscoreIocs)} IOCs into a new list.')

    return cinscoreIocs

def parse_coinblocker():
    '''
    Reads out the CINS Score IOC file and parses the first 10K IOCs
    '''
    # Empty list for new IOCs
    coinblockerIocs = []
    
    # Readout the file and close it
    coinblockerIocFile = open(COINBLOCKER_FILE_NAME, 'r')
    coinblockerIocList = coinblockerIocFile.readlines()
    coinblockerIocFile.close()

    # List for domains that have been seen
    seenDomains = []
    
    # Parse the list and strip the newline
    for ioc in coinblockerIocList:
        # IP Sets accept up to 10K values, stop there
        if len(coinblockerIocs) < 10000:
            try:
                ioc = ioc.replace('\n','')
                # Find the top-level domain instead
                splitter = ioc.split('.')
                domain = f'{splitter[-2]}.{splitter[-1]}'
                if domain not in seenDomains:
                    seenDomains.append(domain)
                else:
                    continue
                # Attempt to transform domain IOC into an IP
                ip = domain_to_ip(domain)
                if ip == None:
                    continue
                # Check to ensure the IP Address is good...
                ipaddress.ip_address(ip)
                # Write into the list as a CIDR
                if ip not in coinblockerIocs:
                    coinblockerIocs.append(f'{ip}/32')
                else:
                    continue
            except ValueError:
                print(f'{ip} is invalid!')
                continue
        else:
            break

    del seenDomains

    print(f'Parsed {len(coinblockerIocs)} IOCs into a new list.')

    return coinblockerIocs

def domain_to_ip(domain):
    '''
    This function receives Domain IOCs and attempts to convert them into IP addresses using `socket`
    '''
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        print(f'Socket error {e} encountered for {domain}')
        ip = None

    return ip

def wafv2_ip_set_commander():
    '''
    Controls or updates multiple IP Sets from various IOC feeds
    '''
    # Download fresh feeds
    download_ioc_feeds()

    # Retrieve parsed IOCs
    cinsscoreIocs = parse_cinsscore()
    coinblockerIocs = parse_coinblocker()

    # Determine if the IP Sets exist. Create a list of IP Sets to reference, if any exist
    ipsets = []

    # Save ListIpSets results to a variable, it will need to be accessed multiple times
    listIpSets = wafv2.list_ip_sets(Scope='REGIONAL')['IPSets']

    # Write unique WAFv2 IP Set names into the list
    for ipset in listIpSets:
        ipsetName = ipset['Name']
        if ipsetName not in ipsets:
            ipsets.append(ipsetName)

    # CINS Score Create/Update loop
    if CINSSCORE_IPSET_NAME not in ipsets:
        cinsscoreIpSetArn = waf_ip_set_creator(
            ip_set_name=CINSSCORE_IPSET_NAME,
            ioc_payload=cinsscoreIocs
        )
    else:
        for ipset in listIpSets:
            if ipset['Name'] == CINSSCORE_IPSET_NAME:
                ipSetId = ipset['Id']
                ipSetLockToken = ipset['LockToken']
                cinsscoreIpSetArn = ipset['ARN']
                waf_ip_set_updater(
                    ip_set_name=CINSSCORE_IPSET_NAME,
                    ip_set_id=ipSetId,
                    ip_set_lock_token=ipSetLockToken,
                    ioc_payload=cinsscoreIocs
                )
                break
            else:
                continue

    # Coinblocker Create/Update loop
    if COINBLOCKER_IPSET_NAME not in ipsets:
        coinblockerIpSetArn = waf_ip_set_creator(
            ip_set_name=COINBLOCKER_IPSET_NAME,
            ioc_payload=coinblockerIocs
        )
    else:
        for ipset in listIpSets:
            if ipset['Name'] == COINBLOCKER_IPSET_NAME:
                ipSetId = ipset['Id']
                ipSetLockToken = ipset['LockToken']
                coinblockerIpSetArn = ipset['ARN']
                waf_ip_set_updater(
                    ip_set_name=COINBLOCKER_IPSET_NAME,
                    ip_set_id=ipSetId,
                    ip_set_lock_token=ipSetLockToken,
                    ioc_payload=coinblockerIocs
                )
                break
            else:
                continue
    
    return cinsscoreIpSetArn, coinblockerIpSetArn

def waf_ip_set_creator(ip_set_name, ioc_payload):
    '''
    Receives a name and IOC payload from `wafv2_ip_set_commander` and creates a new IP Set and returns the ARN
    '''
    # Generate timestamp for IP Set Description
    dtgNow = str(datetime.utcnow())
    # Create the IP Set
    try:
        r = wafv2.create_ip_set(
            Name=ip_set_name,
            Scope='REGIONAL',
            Description=f'IP Set corresponding to IOCs of the named IP Set - IOCs loaded at {dtgNow}',
            IPAddressVersion='IPV4',
            Addresses=ioc_payload,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': ip_set_name
                }
            ]
        )
        ipSetArn = r['Summary']['ARN']
        # Wait 15 seconds for the IP Set to "stabilize"
        print(f'Succesfully created a new IP Set {ip_set_name}. Waiting 7 seconds for the IP Set to stabilize')
        sleep(7)
    except botocore.exceptions.ClientError as error:
        raise error

    return ipSetArn

def waf_ip_set_updater(ip_set_name, ip_set_id, ip_set_lock_token, ioc_payload):
    '''
    Receives a name, ID, lock token, and IOC payload from `wafv2_ip_set_commander` and updates an existing IP Set and returns the ARN
    '''
    # Generate timestamp for IP Set Description
    dtgNow = str(datetime.utcnow())
    # Update the IP Set
    try:
        wafv2.update_ip_set(
            Name=ip_set_name,
            Scope='REGIONAL',
            Id=ip_set_id,
            Description=f'IP Set corresponding to IOCs of the named IP Set - IOCs loaded at {dtgNow}',
            Addresses=ioc_payload,
            LockToken=ip_set_lock_token
        )
        print(f'Sucessfully updated IP Set {ip_set_name}')
    except Exception as e:
        raise e

def day15_placeholder():
    '''
    Nothing yet...
    '''
    # With multiple `return` statements, the values are provided as a tuple which can be accessed like a list
    ipSets = wafv2_ip_set_commander()

    print(f'CINS Score IP Set ARN is {ipSets[0]}')
    print(f'Coinblocker IP Set ARN is {ipSets[1]}')

day15_placeholder()