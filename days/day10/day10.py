import os
import boto3
import json
import base64
import zlib

#SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
#sns = boto3.client('sns')

def lambda_handler(event, context):
    # parse CWL event
    data = event.get('awslogs', {}).get('data')
    log_parser(data)

def log_parser(data):
    # Base64 Decode, decompress with ZLIB, load into a dict with json.loads
    records = json.loads(zlib.decompress(base64.b64decode(data), 16 + zlib.MAX_WBITS))
    # Loop through the query log message
    for ql in records['logEvents']:
        # parse the nested "message" object and load this into JSON as well
        msg = json.loads(ql['message'])
        try:
            # If a log is not flagged by a firewall, it will not have the associated keys, any KeyError can be ignored
            fwRuleAction = msg['firewall_rule_action']
            fwDomainListId = msg['firewall_domain_list_id']
            # Parse regular logs
            acctId = msg['account_id']
            awsRegion = msg['region']
            vpcId = msg['vpc_id']
            queryTime = msg['query_timestamp']
            queryDestination = msg['query_name']
            sourceId = msg['srcids']['instance']
            # Assemble the message
            message = f'Query to {queryDestination} from {sourceId} within VPC {vpcId} in AWS Account {acctId} in {awsRegion} matched the DNS Firewall Domain List {fwDomainListId} with the {fwRuleAction} Action at {queryTime}.'
            
            print(message)
            # TODO: Implement
            #send_to_sns(message)
        except KeyError:
            continue

def send_to_sns(message):
    # TODO: Implement
    payload = {'Message': message}
    '''
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=payload
        )
    except Exception as e:
        print(e)
    '''