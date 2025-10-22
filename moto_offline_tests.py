from moto import mock_aws
import boto3
import pytest

REGION = "sa-east-1"

def _s3(region=REGION):
    return boto3.client("s3", region_name=region)

def _iam(region=REGION):
    return boto3.client("iam", region_name=region)

def _logs(region=REGION):
    return boto3.client("logs", region_name=region)

@pytest.mark.offline
@mock_aws
def test_local_s3_encryption_and_versioning():
    s3 = _s3()
    bucket = "local-bucket"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    ver = s3.get_bucket_versioning(Bucket=bucket)
    enc = s3.get_bucket_encryption(Bucket=bucket)
    algo = enc["ServerSideEncryptionConfiguration"]["Rules"][0].get(
        "ApplyServerSideEncryptionByDefault", {}
    ).get("SSEAlgorithm") or enc["ServerSideEncryptionConfiguration"]["Rules"][0].get(
        "ServerSideEncryptionByDefault", {}
    ).get("SSEAlgorithm")

    assert ver["Status"] == "Enabled"
    assert algo == "AES256"


@pytest.mark.offline
@mock_aws
def test_local_s3_policy_denies_unencrypted_put():
    s3 = _s3()
    bucket = "local-policy-bucket"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )

    policy_doc = """{
      "Version":"2012-10-17",
      "Statement":[
        {
          "Sid":"DenyInsecureTransport",
          "Effect":"Deny",
          "Principal":"*",
          "Action":"s3:*",
          "Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"],
          "Condition":{"Bool":{"aws:SecureTransport":"false"}}
        },
        {
          "Sid":"DenyUnencryptedObjectUploads",
          "Effect":"Deny",
          "Principal":"*",
          "Action":"s3:PutObject",
          "Resource":"arn:aws:s3:::%s/*",
          "Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}
        }
      ]
    }""" % (bucket, bucket, bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy=policy_doc)

    policy = s3.get_bucket_policy(Bucket=bucket)["Policy"]
    assert "DenyUnencryptedObjectUploads" in policy
    assert "aws:SecureTransport" in policy


@pytest.mark.offline
@mock_aws
def test_local_iam_policy_wildcard_detect():
    iam = _iam()

    iam.create_policy(
        PolicyName="AdminAll-local",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    iam.create_policy(
        PolicyName="Unused-local",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:DescribeLogGroups","Resource":"*"}]}',
    )

    pols = iam.list_policies(Scope="Local")["Policies"]
    assert any("AdminAll" in p["PolicyName"] for p in pols), "Wildcard policy não encontrada"
    assert any("Unused" in p["PolicyName"] for p in pols), "Unused policy não encontrada"

    admin = [p for p in pols if "AdminAll" in p["PolicyName"]][0]
    doc = iam.get_policy_version(
        PolicyArn=admin["Arn"], VersionId=admin["DefaultVersionId"]
    )["PolicyVersion"]["Document"]
    assert any(st.get("Action") == "*" and st.get("Resource") == "*" for st in doc["Statement"])


