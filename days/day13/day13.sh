echo 'Enter a name for your table:'
read tablename
aws dynamodb create-table \
    --table-name $tablename \
    --attribute-definitions AttributeName=IpAddress,AttributeType=S \
    --key-schema AttributeName=IpAddress,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
sleep 5
aws dynamodb update-time-to-live \
    --table-name $tablename \
    --time-to-live-specification Enabled=true,AttributeName=Ttl