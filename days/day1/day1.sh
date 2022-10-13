sudo apt install -y jq
# Get your Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity | jq '.Account' -r)
echo $AWS_ACCOUNT_ID
# Get your Region
AWS_REGION=$(aws configure get region)
echo $AWS_REGION
# Get your Account name
AWS_ACCOUNT_NAME=$(aws organizations describe-account --account-id $AWS_ACCOUNT_ID | jq '.Account.Name' -r)
echo $AWS_ACCOUNT_NAME
# Get your AWS Organizations ID
AWS_ORGANIZATIONS_PRINCIPAL_ID=$(aws organizations describe-organization | jq '.Organization.Id' -r)
echo $AWS_ORGANIZATIONS_PRINCIPAL_ID