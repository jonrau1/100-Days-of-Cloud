import boto3
import uuid

rt53r = boto3.client('route53resolver')

def create_dnsfw_for_vpc():
    '''
    This function creates and attaches a DNSFW with a managed domain list to all VPCs in your current Region
    '''
    # Create request id
    creatorRequestId = str(uuid.uuid4())
    # Call helper functions
    vpcs = find_vpcs()
    domainListId = find_default_malware_domain_list()
    firewallRuleGroupId = create_firewall_rule_group()

    # Create the DNSFW Rule
    create_firewall_rule(domainListId, firewallRuleGroupId)

    # Associate the Firewall Group with all VPCs
    for vpc in vpcs:
        try:
            rt53r.associate_firewall_rule_group(
                CreatorRequestId=creatorRequestId,
                FirewallRuleGroupId=firewallRuleGroupId,
                VpcId=vpc,
                Priority=101,
                Name=f'{vpc}100DaysOfCloudMalwareAlerts',
            )
            print(f'Associated VPC {vpc} with DNSFW {firewallRuleGroupId}!')
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

def find_default_malware_domain_list():
    '''
    Attempts to find the ID of the Route53 Resolver DNS Firewall Domain List associated with malware domains
    '''
    try:
        for fdl in rt53r.list_firewall_domain_lists()['FirewallDomainLists']:
            if fdl['Name'] == 'AWSManagedDomainsMalwareDomainList':
                domainListId = fdl['Id']
                break
            else:
                continue
    except Exception as e:
        raise e

    print('Found the Domain List ID for the "AWSManagedDomainsMalwareDomainList" managed list.')

    return domainListId

def create_firewall_rule_group():
    '''
    Creates and returns the ID of a finalized Route53 Resolver DNS Firewall Rule Group to be associated with VPCs
    '''
    # Create request id
    creatorRequestId = str(uuid.uuid4())

    try:
        firewallRuleGroupId = rt53r.create_firewall_rule_group(
            CreatorRequestId=creatorRequestId,
            Name='100DaysOfCloudMalwareRules',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': '100DaysOfCloudMalwareRules'
                }
            ]
        )['FirewallRuleGroup']['Id']
    except Exception as e:
        raise e

    print('Created a new Route53 Resolver DNS Firewall Rule Group.')

    return firewallRuleGroupId

def create_firewall_rule(domain_list_id, firewall_group_id):
    '''
    Creates a Route53 Resolver DNS Firewall Rule that contains the managed Domain List for malware domains
    '''
    # Create request id
    creatorRequestId = str(uuid.uuid4())

    try:
        rt53r.create_firewall_rule(
            CreatorRequestId=creatorRequestId,
            FirewallRuleGroupId=firewall_group_id,
            FirewallDomainListId=domain_list_id,
            Priority=101,
            Action='ALERT',
            Name='100DaysOfCloudMalwareAlerts'
        )
    except Exception as e:
        raise e

    print(f'Created ALERT rule for Route53 Resolver DNS Firewall Rule Group {firewall_group_id}')

create_dnsfw_for_vpc()