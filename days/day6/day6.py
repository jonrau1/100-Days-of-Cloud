import boto3
import json

sts = boto3.client('sts')
AWS_ACCOUNT_ID = sts.get_caller_identity()['Account']
del sts

def get_aws_regions():
    '''
    Retrieves all opted-in AWS Regions for this Account
    '''
    ec2 = boto3.client('ec2')

    awsRegions = []

    try:
        # Get all Regions we are opted in for
        for r in ec2.describe_regions()['Regions']:
            regionName = str(r['RegionName'])
            optInStatus = str(r['OptInStatus'])
            if optInStatus == 'not-opted-in':
                continue
            else:
                awsRegions.append(regionName)
    except Exception as e:
        raise e
        
    print('Got all AWS Regions')

    del ec2

    return awsRegions

def default_sg_sniffer():
    '''
    This function commands all other functions, finds and assembles a list of resources and
    writes to a file using multiprocessing
    '''

    # TODO: Consider multiprocessing this bullshit?

    print(f'Locating EC2 instances using the Default Security Group.')
    ec2Instances = find_ec2_using_default()
    print(f'Found {len(ec2Instances)} EC2 instance(s) using the Default Security Group.')

    print(f'Locating RDS instances using the Default Security Group.')
    rdsInstances = find_rds_using_default()
    print(f'Found {len(rdsInstances)} RDS instance(s) using the Default Security Group.')

    print(f'Locating ALB load balancers using the Default Security Group.')
    albLbs = find_alb_using_default()
    print(f'Found {len(albLbs)} ALB load balancer(s) using the Default Security Group.')

    # Use extend() to combine the lists before writing to file - we will add them to the first list, "ec2Instances"
    # only in the event that there are actually things to write
    if (
        len(ec2Instances) and 
        len(rdsInstances) and 
        len(albLbs) != 0
    ):
        ec2Instances.extend(rdsInstances)
        ec2Instances.extend(albLbs)
        
        # Write the new chonky combined list to JSON for all your reporting-related terror to inflict upon the world
        with open('./default_sg_resources.json', 'w') as jsonfile:
            json.dump(
                ec2Instances,
                jsonfile,
                indent=2,
                default=str
            )

        print('Wrote all non-compliant resources to file.')
    else:
        print('There are not any non-compliant resources to write to a file.')

def find_ec2_using_default():
    '''
    Searches all Regions for EC2 instances using the Default Security Group
    '''
    awsRegions = get_aws_regions()

    # Empty list for instances
    instances = []

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an EC2 client
        session = boto3.Session(region_name=region)
        ec2 = session.client('ec2')
        paginator = ec2.get_paginator('describe_instances')
        # Paginate through EC2s
        for page in paginator.paginate(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': [
                        'running',
                        'stopped'
                    ]
                }
            ]
        ):
            for r in page['Reservations']:
                for i in r['Instances']:
                    instanceId = i['InstanceId']
                    # Loop SGs, there is typically only one, but this checks for more
                    for sg in i['SecurityGroups']:
                        # Continue looping, unless a "default" SG is found, then add instance to list & break
                        if sg['GroupName'] == 'default':
                            defaultEc2Dict = {
                                'AccountId': AWS_ACCOUNT_ID,
                                'AwsRegion': region,
                                'ResourceId': instanceId,
                                'ResourceType': 'EC2Instance'
                            }
                            # append to list
                            instances.append(defaultEc2Dict)
                            break
                        else:
                            continue

    return instances

def find_rds_using_default():
    '''
    Searches all Regions for RDS instances using the Default Security Group
    '''
    awsRegions = get_aws_regions()

    # Empty list for instances
    instances = []

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an RDS client and an EC2 client
        session = boto3.Session(region_name=region)
        rds = session.client('rds')
        # EC2 Client is needed to find the name associated to an SG by ID
        ec2 = session.client('ec2')
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for r in page['DBInstances']:
                instanceId = r['DBInstanceIdentifier']
                # Loop SGs, there is typically only one, but this checks for more
                for sg in r['VpcSecurityGroups']:
                    sgId = sg['VpcSecurityGroupId']
                    # Pass the SG ID to the DescribeSecurityGroups API to parse the name. If the name is default add
                    # the DB information to the list and break the loop
                    if ec2.describe_security_groups(GroupIds=[sgId])['SecurityGroups'][0]['GroupName'] == 'default':
                        defaultRdsDict = {
                            'AccountId': AWS_ACCOUNT_ID,
                            'AwsRegion': region,
                            'ResourceId': instanceId,
                            'ResourceType': 'RDSInstance'
                        }
                        # append to list
                        instances.append(defaultRdsDict)
                        break
                    else:
                        continue

    return instances

def find_alb_using_default():
    '''
    Searches all Regions for Application Load Balancers using the Default Security Group
    '''
    awsRegions = get_aws_regions()

    # Empty list for lbs
    lbalancers = []

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an ELBv2 client and en EC2 client
        session = boto3.Session(region_name=region)
        elbv2 = session.client('elbv2')
        # EC2 Client is needed to find the name associated to an SG by ID
        ec2 = session.client('ec2')
        paginator = elbv2.get_paginator('describe_load_balancers')
        # Paginate through ALBs
        for page in paginator.paginate():
            for l in page['LoadBalancers']:
                lbName = l['LoadBalancerName']
                # Similar to RDS & EC2, ALBs can have multiple load balancers, but like RDS only the ID is returned
                for sg in l['SecurityGroups']:
                    # Pass the SG ID to the DescribeSecurityGroups API to parse the name. If the name is default add
                    # the DB information to the list and break the loop
                    # The list of "SecurityGroups" only returns the IDs as is, no need for additional parsing...
                    if ec2.describe_security_groups(GroupIds=[sg])['SecurityGroups'][0]['GroupName'] == 'default':
                        defaultAlbDict = {
                            'AccountId': AWS_ACCOUNT_ID,
                            'AwsRegion': region,
                            'ResourceId': lbName,
                            'ResourceType': 'ALBLoadBalancer'
                        }
                        # append to list
                        lbalancers.append(defaultAlbDict)
                        break
                    else:
                        continue

    return lbalancers

default_sg_sniffer()