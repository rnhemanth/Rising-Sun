locals {
  bastion_sg_rules_security_group = {
    rule1 = { type = "egress", from = 3389, to = 3389, protocol = "tcp", source_sg = module.security_group_sql.security_group_id, desc = "Allow RDP out to IBI DB Tier" }
  }
  sql_sg_rules_security_group = {
    rule1 = { type = "ingress", from = 135, to = 135, protocol = "tcp", source_sg = module.security_group_bastion.security_group_id, desc = "RPC client-server communication from IBI Bastion SG" }
    rule2 = { type = "ingress", from = 3389, to = 3389, protocol = "tcp", source_sg = module.security_group_bastion.security_group_id, desc = "Windows RDP IBI Bastion SG" }
    rule3 = { type = "ingress", from = 9991, to = 9991, protocol = "tcp", source_sg = module.security_group_bastion.security_group_id, desc = "TCP 9991 from IBI Bastion SG" }
    rule4 = { type = "ingress", from = 1433, to = 1433, protocol = "tcp", source_sg = module.security_group_bastion.security_group_id, desc = "SQL from IBI Bastion SG" }
    rule5 = { type = "ingress", from = 3389, to = 3389, protocol = "tcp", source_sg = module.security_group_bastion.security_group_id, desc = "RDP from IBI Bastion SG" }
  }
}

## Security Group - Standard
module "security_group_standard" {
  # checkov:skip=CKV_TF_1: "Ensure Terraform module sources use a commit hash"
  source                = "git::https://github.com/emlsgroup/terraform-aws-ec2-sg.git?ref=v0.1.0"
  name                  = "${var.name.environment}-core-net-sg-${var.name.service}-${var.name.identifier}-standard-ports"
  use_name_prefix       = false
  description           = "Security group with standard ports"
  vpc_id                = module.vpc.vpc_id
  sg_rules_cidr_blocks  = var.standard_sg_rules_cidr_blocks
  sg_rules_self         = var.standard_sg_rules_self
  sg_rules_security_group = var.standard_sg_rules_security_group
}

## Security Group - Bastion
module "security_group_bastion" {
  # checkov:skip=CKV_TF_1: "Ensure Terraform module sources use a commit hash"
  source                = "git::https://github.com/emlsgroup/terraform-aws-ec2-sg.git?ref=v0.1.0"
  name                  = "${var.name.environment}-core-net-sg-${var.name.service}-bastion"
  use_name_prefix       = false
  description           = "Security group with ibi bastion ports"
  vpc_id                = module.vpc.vpc_id
  sg_rules_cidr_blocks  = var.bastion_sg_rules_cidr_blocks
  sg_rules_self         = var.bastion_sg_rules_self
  sg_rules_security_group = local.bastion_sg_rules_security_group
}

## Security Group - SQL
module "security_group_sql" {
  # checkov:skip=CKV_TF_1: "Ensure Terraform module sources use a commit hash"
  source                = "git::https://github.com/emlsgroup/terraform-aws-ec2-sg.git?ref=v0.1.0"
  name                  = "${var.name.environment}-core-net-sg-${var.name.service}-sql"
  use_name_prefix       = false
  description           = "Security group with ibi db ports"
  vpc_id                = module.vpc.vpc_id
  sg_rules_cidr_blocks  = var.sql_sg_rules_cidr_blocks
  sg_rules_self         = var.sql_sg_rules_self
  sg_rules_security_group = local.sql_sg_rules_security_group
}