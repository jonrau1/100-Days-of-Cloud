import boto3

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

def find_default_vpcs():
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
                    print(f'VPC {vpcId} in {region} is the Default VPC!')
                else:
                    print(f'VPC {vpcId} in {region} is a custom VPC.')
        else:
            print(f'There are no VPCs in {region}.')

find_default_vpcs()