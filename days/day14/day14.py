import urllib3
import boto3
import ipaddress
import botocore.exceptions
from datetime import datetime
from time import sleep

wafv2 = boto3.client('wafv2')

CINSSCORE_FILE_NAME = './ci_badguys.txt'
IPSET_NAME = '100DaysOfCloud-CINS'
WAF_RULE_GROUP_NAME = '100DaysOfCloudRules'
WAF_WACL_NAME = '100DaysOfCloudWACL'

def download_cinsscore():
    '''
    Downloads CI Badguys textfile from CINS Score IOC Feed and saves to file
    '''
    # Pool Manager for urllib3
    http = urllib3.PoolManager()

    url = 'http://cinsscore.com/list/ci-badguys.txt'
    try:
        # GET request
        r = http.request(
            'GET',
            url
        )

        with open(CINSSCORE_FILE_NAME, 'wb') as file:
            file.write(r.data)

        r.release_conn()

        print(f'Wrote CINS Score IOC feed to file.')
    except Exception as e:
        raise e

    del http
    del url

    return True

def parse_cinsscore():
    '''
    Reads out the CINS Score IOC file and parses the first 10K IOCs
    '''
    # Download the list
    download_cinsscore()
    # Empty list for new IOCs
    refinedIocs = []
    
    # Readout the file and close it
    iocFile = open(CINSSCORE_FILE_NAME, 'r')
    iocList = iocFile.readlines()
    iocFile.close()

    # Parse the list and strip the newline
    for ioc in iocList:
        # IP Sets accept up to 10K values, stop there
        if len(refinedIocs) < 10000:
            try:
                ioc = ioc.replace('\n','')
                # Check to ensure the IP Address is good...
                ipaddress.ip_address(ioc)
                # Write into the list as a CIDR
                if ioc not in refinedIocs:
                    refinedIocs.append(f'{ioc}/32')
                else:
                    continue
            except ValueError:
                print(f'{ioc} is invalid!')
                continue
        else:
            break

    print(f'Parsed {len(refinedIocs)} IOCs into a new list.')

    return refinedIocs

def wafv2_ip_set_creator():
    '''
    Creates an IP Set from the `parse_cinsscore` function
    '''
    # Generate timestamp for IP Set Description
    dtgNow = str(datetime.utcnow())
    # Create the IP Set
    try:
        r = wafv2.create_ip_set(
            Name=IPSET_NAME,
            Scope='REGIONAL',
            Description=f'IP Set containing CINS Score CI Bad Guys feed - IOCs loaded at {dtgNow}',
            IPAddressVersion='IPV4',
            Addresses=parse_cinsscore(),
            Tags=[
                {
                    'Key': 'Name',
                    'Value': IPSET_NAME
                }
            ]
        )
        ipSetArn = r['Summary']['ARN']
        # Wait 15 seconds for the IP Set to "stabilize"
        print('Waiting 15 seconds for the IP Set to stabilize')
        sleep(15.0)
        print(f'Succesfully created a new IP Set with an ARN of: {ipSetArn}')
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'WAFDuplicateItemException':
            for ipset in wafv2.list_ip_sets(Scope='REGIONAL')['IPSets']:
                if ipset['Name'] == IPSET_NAME:
                    ipSetArn = ipset['ARN']
                    break
                else:
                    continue
        else:
            raise error

    return ipSetArn

def wafv2_rule_group_controller():
    '''
    Creates a WAFv2 Rule Group using the CINS Score IP Set and some other rules...
    '''

    ipSetArn = wafv2_ip_set_creator()

    rules = [
        # BLOCK NIMBROSTRATUS BOTS
        {
            'Name': 'NimbrostratusBlock',
            'Priority': 0,
            'Statement': {
                'ByteMatchStatement': {
                    'SearchString': 'b"Nimbostratus"',
                    'FieldToMatch': {
                        'SingleHeader': {
                            'Name': 'user-agent'
                        }
                    },
                    'TextTransformations': [
                        {
                            'Priority': 0,
                            'Type': 'NONE'
                        },
                        {
                            'Priority': 1,
                            'Type': 'LOWERCASE'
                        }
                    ],
                    'PositionalConstraint': 'CONTAINS'
                }
            },
            'Action': {
                'Block': {
                    'CustomResponse': {
                        'ResponseCode': 418
                    }
                }
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'NimbrostratusBlock'
            }
        },
        # BLOCK MASSCAN BOTS
        {
            'Name': 'MasscanBlocker',
            'Priority': 1,
            'Statement': {
                'ByteMatchStatement': {
                    'SearchString': 'b"masscan"',
                    'FieldToMatch': {
                        'SingleHeader': {
                            'Name': 'user-agent'
                        }
                    },
                    'TextTransformations': [
                        {
                            'Priority': 0,
                            'Type': 'NONE'
                        },
                        {
                            'Priority': 1,
                            'Type': 'LOWERCASE'
                        }
                    ],
                    'PositionalConstraint': 'CONTAINS'
                }
            },
            'Action': {
                'Block': {
                    'CustomResponse': {
                        'ResponseCode': 418
                    }
                }
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'MasscanBlocker'
            }
        },
        # BLOCK IP SET ADDRESS IN SOURCE IP
        {
            'Name': 'IpSetBlockSource',
            'Priority': 3,
            'Statement': {
                'IPSetReferenceStatement': {
                    'ARN': ipSetArn
                }
            },
            'Action': {
                'Block': {
                    'CustomResponse': {
                        'ResponseCode': 418
                    }
                }
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'IpSetBlockSource'
            }
        },
        # BLOCK IP SET ADDRESS IN XFF HEADERS
        {
            'Name': 'IpSetXFFBlock',
            'Priority': 5,
            'Statement': {
                'IPSetReferenceStatement': {
                    'ARN': ipSetArn,
                    'IPSetForwardedIPConfig': {
                        'HeaderName': 'X-Forwarded-For',
                        'FallbackBehavior': 'NO_MATCH',
                        'Position': 'ANY'
                    }
                }
            },
            'Action': {
                'Block': {
                    'CustomResponse': {
                        'ResponseCode': 418
                    }
                }
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'IpSetXFFBlock'
            }
        }
    ]

    # List to contain all unique Rule Group names to perform check against for CREATE or UPDATE
    ruleGroups = []

    for rg in wafv2.list_rule_groups(Scope='REGIONAL')['RuleGroups']:
        if rg['Name'] not in ruleGroups:
            ruleGroups.append(rg['Name'])

    # If the Rule Group is NOT in the list, call the function to create
    if WAF_RULE_GROUP_NAME not in ruleGroups:
        print(f'Rule Group named {WAF_RULE_GROUP_NAME} does not exist, creating it!')
        rgArn = wafv2_rule_group_creator(
            rule_group_rules=rules,
            rule_group_name=WAF_RULE_GROUP_NAME
        )
    else:
        print(f'{WAF_RULE_GROUP_NAME} already exists!')
        for rg in wafv2.list_rule_groups(Scope='REGIONAL')['RuleGroups']:
            if rg['Name'] == WAF_RULE_GROUP_NAME:
                rgArn = rg['ARN']
                break
            else:
                continue

    return rgArn

def wafv2_rule_group_creator(rule_group_rules, rule_group_name):
    '''
    This function creates a brand new WAFv2 Rule Group by receiving a name and set of rules from the `wafv2_rule_group_manager()` function and
    provides the ARN back to the calling function
    '''
    # Generate timestamp for IP Set Description
    dtgNow = str(datetime.utcnow())
    # Create the Rule Group
    try:
        r = wafv2.create_rule_group(
            Name=rule_group_name,
            Scope='REGIONAL',
            Capacity=750,
            Description=f'WAFv2 Rule Group created for 100DaysOfCloud contains an CINS Score IP Set and some scanner blocking - Rules as of {dtgNow}',
            Rules=rule_group_rules,
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_group_name
            },
            Tags=[
                {
                    'Key': 'Name',
                    'Value': rule_group_name
                }
            ]
        )
        rgArn = r['Summary']['ARN']
        print(f'Succesfully created a new Rule Group with an ARN of: {rgArn}')
    except Exception as e:
        raise e

    return rgArn

def wafv2_wacl_creator():
    # Generate timestamp for IP Set Description
    dtgNow = str(datetime.utcnow())
    # Create WACL
    try:
        wafv2.create_web_acl(
            Name=WAF_WACL_NAME,
            Scope='REGIONAL',
            Description=f'Created for 100DaysOfCloud contains an CINS Score IP Set and some scanner blocking - Rules as of {dtgNow}',
            DefaultAction={
                'Allow': {}
            },
            Rules=[
                {
                    'Name': '100DaysOfCloudPrimary',
                    'Priority': 1,
                    'Statement': {
                        'RuleGroupReferenceStatement': {
                            'ARN': wafv2_rule_group_controller()
                        }
                    },
                    "OverrideAction": {
                        "None": {}
                    },
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': '100DaysOfCloudPrimary'
                    }
                }
            ],
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': WAF_WACL_NAME
            },
            Tags=[
                {
                    'Key': 'Name',
                    'Value': WAF_WACL_NAME
                }
            ]
        )
        print(f'Web ACL {WAF_WACL_NAME} has been created!')
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'WAFDuplicateItemException':
            print(f'{WAF_WACL_NAME} Web ACL Already exists!')
        else:
            raise error

wafv2_wacl_creator()