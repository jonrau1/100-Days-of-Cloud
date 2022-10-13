import boto3
import uuid

rt53r = boto3.client('route53resolver')

def create_query_logging_for_vpc():
    '''
    This function creates and attaches a DNS Query Logging Config to all VPCs in your current Region and sends logs to CloudWatch
    '''
    # Create request id
    creatorRequestId = str(uuid.uuid4())
    # Call helper functions
    vpcs = find_vpcs()
    logGroupArn = create_log_group()
    # Create Log Config
    queryLogId = create_query_logging_config(logGroupArn)

    # Attach log config
    for vpc in vpcs:
        try:
            rt53r.associate_resolver_query_log_config(
                ResolverQueryLogConfigId=queryLogId,
                ResourceId=vpc
            )
            print(f'Attached Query Logging Config {queryLogId} to VPC {vpc}.')
        except Exception as e:
            raise e

def find_vpcs():
    '''
    Loops VPCs in your current region and returns a list of them
    '''
    ec2 = boto3.client('ec2')

    vpcs = []
    try:
        for vpc in ec2.describe_vpcs()['Vpcs']:
            vpcId = vpc['VpcId']
            if vpc['State'] != 'available':
                continue
            else:
                if vpcId not in vpcs:
                    vpcs.append(vpcId)
    except Exception as e:
        raise e

    print('Gathered all VPCs in Region.')

    return vpcs

def create_log_group():
    '''
    Creates a CloudWatch Log Group...that's it
    '''
    # Get AWS Account & Region info to generate ARN
    awsRegion = boto3.Session().region_name
    sts = boto3.client('sts')
    awsAccountId = sts.get_caller_identity()['Account']
    del sts

    # Create the Log Group & assemble the ARN
    cwl = boto3.client('logs')
    try:
        cwl.create_log_group(
            logGroupName='/aws/route53/100DaysOfCloudDNSQueryLogs',
            tags={'Name': '100DaysOfCloudDNSQueryLogs'}
        )
    except Exception as e:
        raise e

    logGroupArn = f'arn:aws:logs:{awsRegion}:{awsAccountId}:log-group:/aws/route53/100DaysOfCloudDNSQueryLogs:*'

    print(f'Created CloudWatch Log Group: {logGroupArn}.')
    
    return logGroupArn

def create_query_logging_config(log_group_arn):
    '''
    Creates a Route 53 Resolver Query Logging Configuration setting
    '''
    # Create request id
    creatorRequestId = str(uuid.uuid4())
    
    try:
        queryLogId = rt53r.create_resolver_query_log_config(
            Name='100DaysOfCloudQueryLogging',
            DestinationArn=log_group_arn,
            CreatorRequestId=creatorRequestId,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': '100DaysOfCloudQueryLogging'
                }
            ]
        )['ResolverQueryLogConfig']['Id']
    except Exception as e:
        raise e

    print(f'Created Route 53 Resolver Query Logging Configuration: {queryLogId}.')

    return queryLogId

create_query_logging_for_vpc()