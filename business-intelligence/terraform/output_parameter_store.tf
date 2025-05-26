locals {
  secondary_ips = {
    for server in var.servers :
    server.name => {
      secondary_ip_1 = server.secondary_ip_1
      secondary_ip_2 = server.secondary_ip_2
    }
  }
  subnets = {
    for server in var.servers :
    server.name => server.subnet_id
  }
}

data "aws_subnet" "subnets" {
  for_each = toset(values(local.subnets))
  id       = each.value
}