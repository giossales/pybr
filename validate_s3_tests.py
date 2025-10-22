import re
import boto3
import pytest
from botocore.exceptions import ClientError

# mesmo profile/região que você está usando
SESSION = boto3.session.Session(profile_name="workshop-reader", region_name="sa-east-1")
s3 = SESSION.client("s3")

CLEAN_PREFIX = "gio-exemplo-bucket"
MESSY_PREFIX = "oficina-messy-paula"

def _find_bucket_by_prefix(prefix: str) -> str:
    resp = s3.list_buckets()
    buckets = resp.get("Buckets", [])
    matches = [b for b in buckets if b["Name"].startswith(prefix)]
    if not matches:
        pytest.skip(f"Nenhum bucket encontrado com prefixo '{prefix}'.")
    matches.sort(key=lambda b: b["CreationDate"], reverse=True)
    return matches[0]["Name"]

def _get_sse_algorithm(bucket: str) -> str:
    """Lê o SSEAlgorithm aceitando 'ApplyServerSideEncryptionByDefault' ou 'ServerSideEncryptionByDefault'."""
    resp = s3.get_bucket_encryption(Bucket=bucket)
    rule = resp["ServerSideEncryptionConfiguration"]["Rules"][0]
    default = rule.get("ApplyServerSideEncryptionByDefault") or rule.get("ServerSideEncryptionByDefault") or {}
    return default.get("SSEAlgorithm", "")

def _bucket_policy_text(bucket: str) -> str:
    """Retorna o JSON da bucket policy como string (ou '' se não houver)."""
    try:
        pol = s3.get_bucket_policy(Bucket=bucket)
        return pol.get("Policy", "")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucketPolicy", "NoSuchBucket", "NoSuchEntity"):
            return ""
        raise

@pytest.mark.postprovision
def test_s3_versioning_enabled():
    clean_bucket = _find_bucket_by_prefix(CLEAN_PREFIX)
    resp = s3.get_bucket_versioning(Bucket=clean_bucket)
    assert resp.get("Status") == "Enabled", f"Versioning não está Enabled em {clean_bucket}"

@pytest.mark.postprovision
def test_s3_versioning_missing():
    messy_bucket = _find_bucket_by_prefix(MESSY_PREFIX)
    resp = s3.get_bucket_versioning(Bucket=messy_bucket)
    assert "Status" not in resp, f"Versioning inesperado em {messy_bucket}: {resp}"

@pytest.mark.postprovision
def test_s3_encryption_enabled():
    clean_bucket = _find_bucket_by_prefix(CLEAN_PREFIX)
    algo = _get_sse_algorithm(clean_bucket)
    assert algo == "AES256", f"Criptografia inesperada em {clean_bucket}: {algo}"

@pytest.mark.postprovision
def test_s3_policy_denies_unencrypted_put_on_clean():
    clean_bucket = _find_bucket_by_prefix(CLEAN_PREFIX)
    policy = _bucket_policy_text(clean_bucket)
    assert ('"DenyUnencryptedObjectUploads"' in policy) or ('x-amz-server-side-encryption' in policy), \
        f"Bucket policy do {clean_bucket} não força SSE no PutObject"

@pytest.mark.postprovision
def test_s3_policy_no_deny_unencrypted_on_messy():
    messy_bucket = _find_bucket_by_prefix(MESSY_PREFIX)
    policy = _bucket_policy_text(messy_bucket)
    assert ('"DenyUnencryptedObjectUploads"' not in policy) and ('x-amz-server-side-encryption' not in policy), \
        f"{messy_bucket} parece ter regra de negar upload sem SSE; não era esperado no messy."

@pytest.mark.postprovision
def test_s3_block_public_access_enabled():
    clean_bucket = _find_bucket_by_prefix(CLEAN_PREFIX)
    block = s3.get_public_access_block(Bucket=clean_bucket)["PublicAccessBlockConfiguration"]
    assert all(block.values()), f"PAB incompleto em {clean_bucket}: {block}"

@pytest.mark.postprovision
def test_s3_block_public_access_missing():
    """Passa se o messy NÃO tiver PAB ou se tiver alguma flag False.
       Se vier todas True (baseline da conta), fazemos skip."""
    messy_bucket = _find_bucket_by_prefix(MESSY_PREFIX)
    try:
        block = s3.get_public_access_block(Bucket=messy_bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
            return
        raise
    if not all(block.values()):
        return
    pytest.skip(f"{messy_bucket} tem PAB=True em todas as flags (guardrail da conta); pulando teste negativo.")

@pytest.mark.postprovision
def test_s3_lifecycle_rules_exist():
    clean_bucket = _find_bucket_by_prefix(CLEAN_PREFIX)
    rules = s3.get_bucket_lifecycle_configuration(Bucket=clean_bucket)["Rules"]
    assert any(r.get("Status") == "Enabled" for r in rules), f"Sem lifecycle Enabled em {clean_bucket}"

@pytest.mark.postprovision
def test_s3_lifecycle_missing():
    messy_bucket = _find_bucket_by_prefix(MESSY_PREFIX)
    with pytest.raises(ClientError):
        s3.get_bucket_lifecycle_configuration(Bucket=messy_bucket)
