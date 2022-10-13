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

def default_sg_flayer():
    '''
    Loops through every AWS Region and looks for Default SGs, removes the ingress & egress default rules, adds a new tag,
    and then runs a report if there are any leftover rules
    '''
    awsRegions = get_aws_regions()

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an EC2 client
        session = boto3.Session(region_name=region)
        ec2 = session.client('ec2')
        # Default Security Group always has a Group Name of 'default'
        response = ec2.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': ['default']
                }
            ]
        )
        # Ignore empty returns
        if not response['SecurityGroups']:
            continue
        else:
            # Parse Default SGs. Use For loop as there can be multiple SGs per Region
            for sg in response['SecurityGroups']:
                #print(json.dumps(sg,indent=4,default=str))
                sgId = sg['GroupId']
                # Remove the self-ref SG Rule, if there are any ingress rules
                if sg['IpPermissions']:
                    print(f'Removing ingress for Default SG {sgId} in {region}.')
                    default_sg_ingress_removal(region, sgId)
                # Remove the egress rule, if there are any egress rules
                if sg['IpPermissionsEgress']:
                    print(f'Removing egress for Default SG {sgId} in {region}.')
                    default_sg_egress_removal(region, sgId)
                # Add a new tag to the default SG as a warning
                print(f'Adding new warning name tag to Default SG {sgId} in {region}.')
                default_sg_tagger(region, sgId)
                # Report if there are any left over rules
                print(f'Checking if there are remaining rules for Default SG {sgId} in {region}.')
                default_sg_remaining_rules_report(region, sgId)

def default_sg_ingress_removal(region, security_group_id):
    '''
    Removes the Default SG self-referenced ingress rule ONLY
    '''
    session = boto3.Session(region_name=region)
    ec2 = session.client('ec2')

    try:
        r = ec2.revoke_security_group_ingress(
            DryRun=False,
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [
                        {
                            'GroupId': security_group_id,
                            'UserId': AWS_ACCOUNT_ID
                        }
                    ]
                }
            ]
        )
        if r['Return'] == True:
            print(f'Revoked self-referenced Ingress for Default SG {security_group_id} in {region}.')
        else:
            print(f'Failed to revoke self-referenced Ingress for Default SG {security_group_id} in {region}.')
    except Exception as e:
        print(f'Failed to revoke self-referenced Ingress for Default SG {security_group_id} in {region}.')
        print(e)

def default_sg_egress_removal(region, security_group_id):
    '''
    Removes the Default SG allow-all Egress rule ONLY
    '''
    session = boto3.Session(region_name=region)
    ec2 = session.client('ec2')

    try:
        r = ec2.revoke_security_group_egress(
            DryRun=False,
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0'
                        }
                    ]
                }
            ]
        )
        if r['Return'] == True:
            print(f'Revoked allow-all Egress for Default SG {security_group_id} in {region}.')
        else:
            print(f'Failed to revoke allow-all Egress for Default SG {security_group_id} in {region}.')
    except Exception as e:
        print(f'Failed to revoke allow-all Egress for Default SG {security_group_id} in {region}.')
        print(e)

def default_sg_tagger(region, security_group_id):
    '''
    Adds tags to the Default SG so people know not to touch it...hopefully
    '''
    session = boto3.Session(region_name=region)
    ec2 = session.client('ec2')

    try:
        ec2.create_tags(
            DryRun=False,
            Resources=[security_group_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'DEFAULT_DO_NOT_USE'
                }
            ]
        )
        print(f'Tagged Default SG {security_group_id} in {region}.')
    except Exception as e:
        print(f'Failed to tag Default SG {security_group_id} in {region}.')
        print(e)

def default_sg_remaining_rules_report(region, security_group_id):
    '''
    Describes if there are any other rules left on the default SG
    '''
    session = boto3.Session(region_name=region)
    ec2 = session.client('ec2')

    r = ec2.describe_security_group_rules(
        Filters=[
            {
                'Name': 'group-id',
                'Values': [security_group_id]
            },
        ]
    )
    if r['SecurityGroupRules']:
        print(
            json.dumps(
                r['SecurityGroupRules'],
                indent=4,
                default=str
            )
        )

default_sg_flayer()