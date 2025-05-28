# SFTP and PUBLIC IP
resource "aws_eip" "eip-sftp01" {
  domain = "vpc"
  tags = {
    Name = "${local.project_name}-net-sftp01"
  }
}

resource "aws_eip" "eip-sftp02" {
  domain = "vpc"
  tags = {
    Name = "${local.project_name}-net-sftp02"
  }
}

resource "aws_transfer_server" "sftp" {
  # checkov:skip=CKV_AWS_164: "Ensure Transfer Server is not exposed publicly."
  protocols               = ["SFTP"]
  domain                  = "S3"
  identity_provider_type  = "SERVICE_MANAGED"
  security_policy_name    = "TransferSecurityPolicy-2024-01"
  endpoint_type           = "VPC"
  endpoint_details {
    address_allocation_ids = [aws_eip.eip-sftp01.id, aws_eip.eip-sftp02.id]
    subnet_ids             = [aws_subnet.this["public-01"].id, aws_subnet.this["public-02"].id]
    vpc_id                 = aws_vpc.this.id
    security_group_ids     = [aws_security_group.sftp_sg.id]
  }
  tags = {
    Name = "${local.project_name}-net-sftp"
  }
}

resource "aws_security_group" "sftp_sg" {
  # checkov:skip=CKV2_AWS_5: "Ensure that Security Groups are attached to another resource"
  name        = "${local.project_name}-net-sg-sftp"
  description = "Security group for AWS Transfer Server."
  vpc_id      = aws_vpc.this.id
  tags = {
    Name = "${local.project_name}-net-sg-sftp"
  }
}

resource "aws_security_group_rule" "sftp_sg_ingress_1" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  description = "Ingress SFTP access from VPC"
  security_group_id = aws_security_group.sftp_sg.id
  cidr_blocks = [local.vpc.cidr_block]
}

resource "aws_security_group_rule" "sftp_sg_ingress_2" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  description = "Ingress SFTP access from IBI VPC"
  security_group_id = aws_security_group.sftp_sg.id
  cidr_blocks = [var.ipv4_primary_cidr_block]
}