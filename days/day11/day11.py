import json
import base64
import zlib
import socket

def lambda_handler(event, context):
    # parse CWL event
    log_parser(event.get('awslogs', {}).get('data'))

def log_parser(data):
    # Empty list to contain finished payloads
    payloads = []
    # Base64 Decode, decompress with ZLIB, load into a dict with json.loads
    records = json.loads(zlib.decompress(base64.b64decode(data), 16 + zlib.MAX_WBITS))
    # Loop through the query log message
    for ql in records['logEvents']:
        # parse the nested "message" object and load this into JSON as well
        message = json.loads(ql['message'])
        try:
            # If a log is not flagged by a firewall, it will not have the associated keys, any KeyError can be ignored
            message['firewall_rule_action']
            # Send the pertinent messages to be enriched & write final result to list
            payloads.append(
                log_enrichment_and_normalization(
                    message
                )
            )
        except KeyError:
            continue

    payload_processor(payloads)

def log_enrichment_and_normalization(message):
    # Parse out the query name
    queryName = message['query_name']
    # Try to find out the IP Address...
    try:
        ip = socket.gethostbyname(queryName)
    except Exception as e:
        print(e)
        ip = None
    # Source ID may not be an instance in the future...
    try:
        srcId = message['srcids']['instance']
    except KeyError:
        srcId = None

    payload = {
        'AccountId': message['account_id'],
        'Region': message['region'],
        'VpcId': message['vpc_id'],
        'QueryTimestamp': message['query_timestamp'],
        'QueryName': queryName,
        'QueryIpAddress': ip,
        'QueryType': message['query_type'],
        'QueryClass': message['query_class'],
        'Rcode': message['rcode'],
        'Answers': str(message['answers']),
        'SrcAddr': message['srcaddr'],
        'SrcPort': message['srcport'],
        'Transport': message['transport'],
        'SrcId': srcId,
        'FirewallRuleAction': message['firewall_rule_action'],
        'FirewallRuleGroupId': message['firewall_rule_group_id'],
        'FirewallDomainListId': message['firewall_domain_list_id']
    }

    return payload

def payload_processor(payloads):
    # Receive and send chunks of payloads to SQS
    for payload in payloads:
        print(
            json.dumps(
                payload,
                indent=2,
                default=str
            )
        )