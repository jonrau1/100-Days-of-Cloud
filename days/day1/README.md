# 100 Days of Cloud Day 1

[Post Link](https://www.linkedin.com/feed/update/urn:li:activity:6980913548331786240/)

## Post Contents

Time to do something I never partook in: #100daysofcloud #100daysofcybersecurity. It kind of favors the micro-content and maybe you will learn a thing or two from your (allegedly) Favorite CISO.

In AWS, you're going to run into times where you need to know your Account ID, Account Name, Organizations ID, or current Region. Maybe it's for uniqueness, maybe its to provide to another command, maybe it is to fill in an environment variable, or maybe to write an IAM policy condition, or just because you want to know. Don't get so caught up in justification.

These are some of my favorite. Using Carbon to create these nifty terminal pictures too. I'll mostly focus on AWS with CLI & Python, may throw in some M365 E5 Security stuff in there too just to keep you on your toes. Feel free to make requests too and engage with me, or suffer the consequences of learning NOTHING HAHHAHAHAHA...okay, I'll stop.

Anyway, code for you copy-paste people:

```bash
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
```

Stay Dangerous

#security #learning #python #cli #aws #cloudsecurity #bash