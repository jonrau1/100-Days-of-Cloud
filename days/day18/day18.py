import os
import boto3
import uuid
import json
import sys
import urllib3

# Variable for an HTTP(S) endpoint with the WAF attached...if you don't do this the final function won't do anything
try:
    WAF_ENABLED_ENDPOINT_DNS_NAME = os.environ['WAF_ENABLED_ENDPOINT_DNS_NAME']
except KeyError:
    WAF_ENABLED_ENDPOINT_DNS_NAME = None
# export WAF_ENABLED_ENDPOINT_DNS_NAME='DNS_HERE_YO'

sts = boto3.client('sts')
AWS_ACCOUNT_ID = sts.get_caller_identity()['Account']
AWS_REGION = boto3.Session().region_name
del sts

def logging_bucket_creator():
    '''
    Creates a bucket for WAFv2 Logs with a UUID at the end...so you should probably not do that
    '''
    s3 = boto3.client('s3')

    # All buckets ***MUST MUST MUST*** start with "aws-waf-logs-"
    bucketName = str(f'aws-waf-logs-{AWS_ACCOUNT_ID}-{uuid.uuid4()}')

    # Create a Bucket...duh
    try:
        s3.create_bucket(
            ACL='private',
            Bucket=bucketName,
            CreateBucketConfiguration={
                'LocationConstraint': AWS_REGION
            }
        )
        print(f'Created logging bucket named {bucketName}.')
    except Exception as e:
        raise e

    return bucketName

def logging_bucket_policy_manager():
    '''
    Attaches a Bucket Policy to the WAFv2 Logs bucket created in `logging_bucket_creator()`
    '''
    s3 = boto3.client('s3')

    # Get the bucket Name, create an ARN
    bucketName = logging_bucket_creator()
    bucketArn = f'arn:aws:s3:::{bucketName}'

    # Fill in Policy...
    bucketPolicy = {
        'Version':'2012-10-17',
        'Statement':[
            {
                'Sid':'AWSLogDeliveryWrite',
                'Effect':'Allow',
                'Principal':{
                    'Service':'delivery.logs.amazonaws.com'
                },
                'Action':'s3:PutObject',
                'Resource':f'{bucketArn}/*',
                'Condition':{
                    'StringEquals':{
                        's3:x-amz-acl':'bucket-owner-full-control',
                        'aws:SourceAccount':[
                            f'{AWS_ACCOUNT_ID}'
                        ]
                    },
                    'ArnLike':{
                        'aws:SourceArn':[
                            f'arn:aws:logs:region:{AWS_ACCOUNT_ID}:*'
                        ]
                    }
                }
            },
            {
                'Sid':'AWSLogDeliveryAclCheck',
                'Effect':'Allow',
                'Principal':{
                    'Service':'delivery.logs.amazonaws.com'
                },
                'Action':'s3:GetBucketAcl',
                'Resource':f'{bucketArn}',
                'Condition':{
                    'StringEquals':{
                        'aws:SourceAccount':[
                            f'{AWS_ACCOUNT_ID}'
                        ]
                    },
                    'ArnLike':{
                        'aws:SourceArn':[
                            f'arn:aws:logs:region:{AWS_ACCOUNT_ID}:*'
                        ]
                    }
                }
            }
        ]
    }

    try:
        s3.put_bucket_policy(
            Bucket=bucketName,
            Policy=json.dumps(bucketPolicy)
        )
        print(f'Attached policy to {bucketName}')
    except Exception as e:
        raise e

    return bucketArn

def waf_logger():
    '''
    Finds all WAFs in your Region, creates and attaches a logging configuration to them
    '''
    wafv2 = boto3.client('wafv2')

    # Get the bucket ARN
    bucketArn = logging_bucket_policy_manager()

    # Get a list of all Web ACLs
    allWacls = []
    for wacl in wafv2.list_web_acls(Scope='REGIONAL')['WebACLs']:
        if wacl['ARN'] not in allWacls:
            allWacls.append(wacl['ARN'])

    print(f'Retrieved {len(allWacls)} WAF Web ACLs for your Region.')

    # Logging filter to DROP any "ALLOW", uncomment this and the parameter in the "PutLoggingConfiguration" call below
    '''
    loggingFilter = {
        'Filters': [
            {
                'Behavior': 'DROP',
                'Requirement': 'MEETS_ANY',
                'Conditions': [
                    {
                        'ActionCondition': {
                            'Action': 'ALLOW'
                        }
                    }
                ]
            },
        ],
        'DefaultBehavior': 'KEEP'
    }
    '''

    # Create the logging configurations
    try:
        for wacl in allWacls:
            wafv2.put_logging_configuration(
                LoggingConfiguration={
                    'ResourceArn': wacl,
                    'LogDestinationConfigs': [bucketArn],
                    'ManagedByFirewallManager': False,
                    #'LoggingFilter': loggingFilter
                }
            )
            print(f'Attached logging config to Web ACL {wacl}')
    except Exception as e:
        raise e

    return True

def waf_log_generator():
    '''
    Sends a few requests to your 
    '''
    # Ensure all WAFs are logging
    waf_logger()

    # Pool manager for urllib3
    http = urllib3.PoolManager()

    # Exit if an env var for a target was not provided
    if WAF_ENABLED_ENDPOINT_DNS_NAME == None:
        print('An endpoint protected by WAF was not provided, exiting.')
        sys.exit(2)

    counter = 0

    while counter < 25:
        req = http.request(
            'GET',
            f'{WAF_ENABLED_ENDPOINT_DNS_NAME}/login.aspx'
        )

        print(req.data.decode('utf-8'))
        counter = counter + 1
        print(counter)
    

waf_log_generator()