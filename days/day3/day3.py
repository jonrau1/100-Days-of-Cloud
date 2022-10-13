import boto3
from time import sleep

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

def seek_and_destroy_default_vpcs():
    '''
    Loops through every AWS Region and looks for Default VPCs
    '''
    awsRegions = get_aws_regions()

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an EC2 client
        session = boto3.Session(region_name=region)
        ec2 = session.client('ec2')
        # Find those VPCs - use a list comprehension to determine if there any VPCs to begin with
        if ec2.describe_vpcs()['Vpcs']:
            for vpc in ec2.describe_vpcs()['Vpcs']:
                # Now let's find the default VPC
                vpcId = vpc['VpcId']
                isDefault = vpc['IsDefault']
                if isDefault == True:
                    # supply VPC ID to filter to find any ENIs with a list comprehension
                    if ec2.describe_network_interfaces(
                        Filters=[
                            {
                                'Name': 'vpc-id',
                                'Values': [vpcId]
                            }
                        ]
                    )['NetworkInterfaces']:
                        # ENIs found - likely has workloads or at least a NATGW that you should check on first...
                        print(f'Default VPC {vpcId} in {region} currently has attached ENIs and cannot be automatically deleted!')
                    else:
                        # Time to SOAR the shit out those default VPCs
                        # Delete the IGWs
                        seek_and_destroy_igws(aws_region=region,vpc_id=vpcId)
                        # Delete the Subnets
                        seek_and_destory_subnets(aws_region=region,vpc_id=vpcId)
                        try:
                            ec2.delete_vpc(VpcId=vpcId)
                            print(f'Yeeted {vpcId} in {region} straight to VPC Hell!')
                        except Exception as e:
                            print(f'Failed to delete {vpcId} in {region} due to \n {e}')
                else:
                    print(f'VPC {vpcId} in {region} is a custom VPC.')
        else:
            print(f'There are no VPCs in {region}.')

def seek_and_destroy_igws(aws_region, vpc_id):
    '''
    This function receives a VPC ID and uses it to find, detach and tear asunder any Internet Gateways and skip rope with its entrails
    '''
    session = boto3.Session(region_name=aws_region)
    ec2 = session.client('ec2')
    try:
        # get the IGW for the VPC
        for igw in ec2.describe_internet_gateways(
            Filters=[
                {
                    'Name': 'attachment.vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )['InternetGateways']:
            igwId = igw['InternetGatewayId']
            # detach the IGW and wait for 2 seconds because a waiter does not exist and I do not want to write one...
            ec2.detach_internet_gateway(
                DryRun=False,
                InternetGatewayId=igwId,
                VpcId=vpc_id
            )
            sleep(2)
            ec2.delete_internet_gateway(
                DryRun=False,
                InternetGatewayId=igwId
            )
            print(f'Internet Gateway for {vpc_id} in {aws_region} was completely and utterly destroyed!')
    except Exception as e:
        print(f'Encountered error trying to remove/delete IGWs for {vpc_id} in {aws_region} \n {e}')

def seek_and_destory_subnets(aws_region, vpc_id):
    '''
    This function receives a VPC ID and uses it to find, and absolutely crush any and all Subnets brazen enough to exist
    '''
    session = boto3.Session(region_name=aws_region)
    ec2 = session.client('ec2')
    try:
        for subnet in ec2.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )['Subnets']:
            subnetId = subnet['SubnetId']
            ec2.delete_subnet(
                SubnetId=subnetId,
                DryRun=False
            )
        print(f'All Subnets for {vpc_id} in {aws_region} were beaten to a pulp and have left this mortal coil!')
    except Exception as e:
        print(f'Encountered error trying to delete Subnets for {vpc_id} in {aws_region} \n {e}')

seek_and_destroy_default_vpcs()