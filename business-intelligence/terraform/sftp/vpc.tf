# VPC
resource "aws_vpc" "this" {
  cidr_block           = local.vpc.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = local.vpc.tag
  }
}

resource "aws_default_security_group" "default_sg" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${local.project_name}-net-sg-default"
  }
}

resource "aws_cloudwatch_log_group" "log_group" {
  name              = "${local.project_name}-net-vpc-log-group"
  kms_key_id        = module.infra.key_arn
  retention_in_days = 365
}

resource "aws_flow_log" "vpc_flow_logs" {
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  vpc_id               = aws_vpc.this.id
  log_destination      = aws_cloudwatch_log_group.log_group.arn
  iam_role_arn         = aws_iam_role.cw_logs_iam_role.arn

  tags = {
    Name = "${local.project_name}-net-vpc-flowlogs"
  }
}

resource "aws_iam_role" "cw_logs_iam_role" {
  name               = "${local.project_name}-sec-iam-VpcFlowLogsToCloudWatch-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["vpc-flow-logs.amazonaws.com"]
      },
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "cw_logs_inline_policy_attachment" {
  # checkov:skip=CKV_AWS_290: "Ensure IAM policies does not allow write access without constraints"
  # checkov:skip=CKV_AWS_355: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
  name = "allow-access-to-cw-logs"
  role = aws_iam_role.cw_logs_iam_role.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}

#Subnet's
resource "aws_subnet" "this" {
  for_each                = local.subnets
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.availability_zone
  cidr_block              = each.value.cidr_block
  map_public_ip_on_launch = false
  tags = {
    Name = each.value.tag
  }
}

resource "aws_internet_gateway" "this" {
  count  = local.vpc.internet_gateway ? 1 : 0
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.project_name}-net-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }
  tags = {
    Name = "${local.project_name}-net-rt-public"
  }
}

resource "aws_route_table_association" "public" {
  for_each = {
    for k, v in local.subnets : k => v
  }
  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.public.id
}