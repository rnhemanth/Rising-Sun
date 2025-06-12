locals {
  project_name = "${var.environment}-ibi-sftp"
  az_names     = sort(data.aws_availability_zones.available.names)
  vpc = {
    cidr_block       = var.sftp_ipv4_primary_cidr_block
    tag              = "${local.project_name}-net-vpc"
    internet_gateway = true
  }
  subnets = {
    public-01 = {
      availability_zone = local.az_names[0]
      cidr_block        = cidrsubnet(var.sftp_ipv4_primary_cidr_block, 1, 0)
      tag               = "${local.project_name}-net-sub-public-01"
      nat_gateway       = false
    }
    public-02 = {
      availability_zone = local.az_names[1]
      cidr_block        = cidrsubnet(var.sftp_ipv4_primary_cidr_block, 1, 1)
      tag               = "${local.project_name}-net-sub-public-02"
      nat_gateway       = false
    }
  }
  transfer_users = jsondecode(var.transfer_users)
}