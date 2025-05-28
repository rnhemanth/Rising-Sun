module "sftp_s3_bucket" {
  # checkov:skip=CKV_TF_1: "Ensure Terraform module sources use a commit hash"
  source = "git::https://github.com/emisgroup/terraform-aws-s3.git?ref=v1.0.2"

  bucket = "${local.project_name}-plat-s3-sftp"
  tags   = var.tags
  # Bucket policies
  attach_policy                   = true
  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true
  # S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  expected_bucket_owner   = data.aws_caller_identity.current.account_id

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.kms.key_arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}