import boto3
import socket
import nmap3
import json

# Instantiate a NMAP scanner for TCP scans to define ports
nmap = nmap3.NmapScanTechniques()

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

def public_ec2_scan_commander():
    '''
    Searches all Regions for Public EC2 instances, evaluates their security group rules, and conducts basic
    scans against them with NMAP and returns a list of scanned instances to another function to write to file
    '''
    awsRegions = get_aws_regions()

    # Empty list for instances with NMAP Results
    instances = []

    for region in awsRegions:
        # Create a new Session for the Region and pass it to an EC2 client
        session = boto3.Session(region_name=region)
        ec2 = session.client('ec2')
        paginator = ec2.get_paginator('describe_instances')
        # Paginate through RUNNING EC2s
        for page in paginator.paginate(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running']
                }
            ]
        ):
            for r in page['Reservations']:
                for i in r['Instances']:
                    # Check if the Instance is public
                    try:
                        pubIp = str(i['PublicIpAddress'])
                    except KeyError:
                        pubIp = None
                    try:
                        pubDns = str(i['PublicDnsName'])
                        # Public DNS is cheeky and will return an empty string instead of None >:(
                        if pubDns == '':
                            pubDns = None
                        else:
                            pubDns = pubDns
                    except KeyError:
                        pubDns = None
                    # Create our own Bool for Public-facing EC2 instances
                    if pubIp != None or pubDns != None:
                        isPublic = True
                    else:
                        isPublic = False
                    # Skip non-public instances
                    if isPublic == False:
                        continue
                    else:
                        instanceId = i['InstanceId']
                        # Loop SGs, there is typically only one, but this checks for more
                        for sg in i['SecurityGroups']:
                            # Feed the Security Group ID to another function and receive back info if
                            # there are port:address pairs that are open to the public internet
                            sgId = sg['GroupId']
                            portTargets = security_group_targeting_intel(sgId, region)
                            # Transform Python list to a comma-separated string if there is more than one target
                            if len(portTargets) > 1:
                                portTargetsString = ','.join(portTargets)
                            else:
                                portTargetsString = portTargets[0]
                            if (pubIp == None and pubDns != None): 
                                pubIp = socket.gethostbyname(pubDns)
                            nmapResults = nmap_scan(instanceId, region, pubIp, portTargetsString)
                            if nmapResults == None:
                                continue
                            else:
                                scanDict = {
                                    'InstanceId': instanceId,
                                    'PublicIp': pubIp,
                                    'AwsRegion': region,
                                    'NmapResults': nmapResults
                                }
                                instances.append(scanDict)

    print(f'Completed all scans!')

    return instances
                          
def security_group_targeting_intel(security_group_id, aws_region):
    '''
    Parses a Security Group's rules and looks for ports that allow traffic from the internet
    '''
    # Create a new Session for the Region and pass it to an EC2 client
    session = boto3.Session(region_name=aws_region)
    ec2 = session.client('ec2')

    # Empty list to contain port targets
    ports = []

    for rule in ec2.describe_security_groups(GroupIds=[security_group_id])['SecurityGroups'][0]['IpPermissions']:
        # Skip rules without an IPv4 CIDR
        if not rule['IpRanges']:
            continue
        else:
            # skip rules that do not allow traffic from the internet and that are not TCP
            if (
                rule['IpRanges'][0]['CidrIp'] != '0.0.0.0/0' or
                rule['IpProtocol'] != 'tcp'
            ):
                continue
            else:
                # write starting port to list if it's not been seen
                fromPort = str(rule['FromPort'])
                if fromPort not in ports:
                    ports.append(fromPort)
                else:
                    continue

    return ports

def nmap_scan(instance_id, region, public_ip, port_range):
    '''
    Performs a TCP scan of a given EC2 instance on a specific set of ports and returns the results
    '''
    print(f'Scanning {instance_id} in {region} on port(s) {port_range} on IP {public_ip}.')

    try:
        raw = nmap.nmap_tcp_scan(
            public_ip,
            args=f'-Pn -p {port_range}'
        )
        results = raw[public_ip]['ports']
    except KeyError:
        results = None

    return results

def nmap_report_to_file():
    '''
    Writes the NMAP scan results to a JSON file
    '''
    nmapResults = public_ec2_scan_commander()
    if nmapResults:
        with open('./ec2_nmap_scan_results.json', 'w') as jsonfile:
            json.dump(
                nmapResults,
                jsonfile,
                default=str,
                indent=4
            )

nmap_report_to_file()