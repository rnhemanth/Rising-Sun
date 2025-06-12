resource "aws_transfer_ssh_key" "this" {
  for_each  = local.transfer_users
  server_id = aws_transfer_server.sftp.id
  user_name = aws_transfer_user.this[each.key].user_name
  body      = each.value.ssh_key
}

resource "aws_transfer_user" "this" {
  for_each       = local.transfer_users
  server_id      = aws_transfer_server.sftp.id
  user_name      = each.value.user_name
  role           = aws_iam_role.transfer_user[each.key].arn
  home_directory = "/${module.sftp_s3_bucket.s3_bucket_id}/${each.value.home_directory}"
  tags = {
    NAME = each.value.user_name
  }
}

resource "aws_iam_role" "transfer_user" {
  for_each = local.transfer_users
  name     = "${each.value.user_name}-transfer-user-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "transfer.amazonaws.com"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
                },
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:transfer:eu-west-2:${data.aws_caller_identity.current.account_id}:user/${aws_transfer_server.sftp.id}/*"
                }
            }
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "transfer" {
  for_each = local.transfer_users
  name     = "${each.value.user_name}-transfer-user-role-policy"
  role     = aws_iam_role.transfer_user[each.key].id

  policy = <<POLICY
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "AllowSpecificAccesstoS3",
           "Effect": "Allow",
           "Action": [
               "s3:GetObject",
               "s3:PutObject",
               "s3:DeleteObject",
               "s3:ListBucketMultipartUploads",
               "s3:AbortMultipartUpload"
           ],
           "Resource": [
               "${module.sftp_s3_bucket.s3_bucket_arn}/${each.value.home_directory}/*"
           ]
       },
       {
           "Sid": "AllowListingInSpecificFolder",
           "Effect": "Allow",
           "Action": [
               "s3:ListBucket"
           ],
           "Resource": "${module.sftp_s3_bucket.s3_bucket_arn}",
           "Condition": {
               "StringLike": {
                   "s3:prefix": "${each.value.home_directory}/*"
               }
           }
       },
       {
           "Sid": "AllowAccesstoKMS",
           "Effect": "Allow",
           "Action": [
               "kms:Encrypt*",
               "kms:Decrypt*",
               "kms:ReEncrypt*",
               "kms:GenerateDataKey*",
               "kms:Describe*"
           ],
           "Resource": [
               "${module.kms.key_arn}"
           ]
       }
   ]
}
POLICY
}

resource "aws_s3_bucket_policy" "AllowSSLRequestsOnly" {
  bucket = module.sftp_s3_bucket.s3_bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Action    = "s3:*"
        Effect    = "Deny"
        Principal = "*"
        Resource = [
          "${module.sftp_s3_bucket.s3_bucket_arn}",
          "${module.sftp_s3_bucket.s3_bucket_arn}/*"
        ]
        Condition = {
          "Bool" : {
            "aws:SecureTransport" : "false"
          }
        }
      }
    ]
  })
}

resource "aws_kms_grant" "transfer_user" {
  for_each          = local.transfer_users
  name              = "trasfer-user-${each.value.user_name}-grant"
  key_id            = module.kms.key_id
  grantee_principal = aws_iam_role.transfer_user[each.key].arn
  operations        = ["Encrypt", "Decrypt", "GenerateDataKey"]
}

resource "aws_s3_object" "create_directory" {
  provider = aws.s3
  # checkov:skip=CKV_AWS_186: "Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK)"
  for_each   = local.transfer_users
  bucket     = module.sftp_s3_bucket.s3_bucket_id
  key        = "${aws_transfer_user.this[each.key].user_name}/blankfile"
  acl        = "private"
  kms_key_id = module.kms.key_arn
}


