import boto3
import csv
import json
from botocore.exceptions import ClientError

# Initialize boto3 clients
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')

def get_bucket_tags(bucket_name):
    try:
        response = s3_client.get_bucket_tagging(Bucket=bucket_name)
        tags = {tag['Key']: tag['Value'] for tag in response['TagSet']}
    except ClientError as e:
        tags = {}
    return tags

def get_bucket_policy(bucket_name):
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        return policy
    except ClientError as e:
        return {}

def extract_iam_roles_from_policy(policy):
    roles = set()
    if not policy:
        return list(roles)
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            aws = principal.get("AWS", [])
            if isinstance(aws, str):
                aws = [aws]
            for arn in aws:
                if ":role/" in arn:
                    roles.add(arn)
    return list(roles)

def main():
    buckets = s3_client.list_buckets()['Buckets']
    with open('s3_buckets_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['BucketName', 'Tags', 'IAMRolesWithAccess', 'PolicyJSON'])

        for bucket in buckets:
            name = bucket['Name']
            tags = get_bucket_tags(name)
            policy = get_bucket_policy(name)
            roles = extract_iam_roles_from_policy(policy)

            writer.writerow([
                name,
                json.dumps(tags),
                json.dumps(roles),
                json.dumps(policy)
            ])

    print("Report generated: s3_buckets_report.csv")

if __name__ == "__main__":
    main()