locals {
  common = read_terragrunt_config("${get_terragrunt_dir()}/../common.terragrunt.hcl")

  # Configure environment
  region          = get_env("AWS_REGION")
  account_id      = get_env("AWS_ACCOUNT_ID")
  environment     = get_env("ENVIRONMENT")
  service         = local.common.locals.service
  project_name    = "${local.environment}-${local.service}"
  region_prefix   = format("%s%s%s", substr("${local.region}", 0, 2), substr("${local.region}", 3, 1), substr("${local.region}", 8, 1))
  service_identifier = "${local.common.locals.service_location}"

  ### SFTP ###
  ssh_key = get_env("ssh_key")
  transfer_users = {
    test = {
      user_name       = "test"
      home_directory  = "test"
      ssh_key         = local.ssh_key # This is a ssh key owned by EWebLogs team to test client connection. A customer ssh key will be manually added via the console
    }
  }

  ### VPC ###
  ipv4_primary_cidr_block      = "100.88.179.64/26" # PLACEHOLDER: From PDF subnet table - verify this matches your actual prd subnet
  sftp_ipv4_primary_cidr_block = "100.88.179.32/27" # PLACEHOLDER: Adjacent CIDR for SFTP - verify available
  tgw_id_backbone              = "tgw-PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Update with your actual PRD TGW ID

  intra_subnets = {
    sql = {
      sql-2a = {
        cidr_block          = "100.88.179.64/27" # PLACEHOLDER: From PDF - verify this works
        availability_zone_id = "euw2-az2" # PLACEHOLDER: Verify this AZ ID is correct for your region
      }
    }
  }

  name = {
    environment = "${local.environment}"
    service     = "eweblogs"
    identifier  = "migration"
  }

  route53_resolver_rules = {
    # PLACEHOLDER: Update these resolver rule IDs based on your PRD environment
    prd_england_emis_web_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    analytica = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    ccmh = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    gplive = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    white = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    emishosting = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    emishome = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    hscn_catch_all = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    shared_services = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    hscn1 = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    hscninet = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    iom = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    jersey = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    cp = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    prod_iom_emis_web_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    prod_scotland_emis_web_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    prod_northernireland_emis_web_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    prod_jersey_emis_web_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
    awshosted_emis_clinical_com = {
      rule_id = "rslvr-rr-PLACEHOLDER_UPDATE_ME"
    }
  }

  ### KMS ###
  key_users = [
    # PLACEHOLDER: Update these ARNs with your actual PRD SSO role ARNs and account ID
    "arn:aws:iam::ACCOUNT_ID_PLACEHOLDER:role/aws-reserved/sso.amazonaws.com/${local.region}/AWSReservedSSO_ROLE_NAME_PLACEHOLDER",
    "arn:aws:iam::ACCOUNT_ID_PLACEHOLDER:role/${local.environment}-eweblogs-migration-ec2-role"
  ]
  
  key_administrators = [
    # PLACEHOLDER: Update with your actual PRD admin SSO role ARN
    "arn:aws:iam::ACCOUNT_ID_PLACEHOLDER:role/aws-reserved/sso.amazonaws.com/${local.region}/AWSReservedSSO_ROLE_NAME_PLACEHOLDER"
  ]

  ### EC2 ###
  ec2_name_prefix      = "ew" # Production prefix
  domain_credentials   = try(get_env("DOMAIN_CREDENTIALS"),"")
  
  # Updated servers based on PDF specifications - PRD has SSIS and SSRS with different specs than DEV
  servers = [
    {
      name           = "SIS001"
      subnet_id      = "subnet-PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Update with actual PRD subnet ID
      az             = "eu-west-2a"
      instance_type  = "r7i.12xlarge" # PDF: Prd SSIS (2019) - 48 *hyper threading disabled, 384GB RAM
      server_function = "eweblogs-ssis"
      server_type    = "db"
      ami_id         = "ami-PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Update with Windows Server 2019 AMI for PRD
      wsus_group     = "scan_only"
      wsus_qsid      = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group = "${local.wsus_policy_scan_only_name}"
      root_volume_size = 128 # PDF: OS disk 128GB
      # PDF shows PRD SSIS volumes: D: 10TB, E: 16TB, F: 5TB, G: 15TB, H: 5TB, I: 15TB, J: 5TB, K: 15TB, L: 2TB, M: 3TB, N: 15TB, O: 14TB
      d_volume_size    = 10000 # D: 10TB (main data volume)
      d_volume_throughput = 1000
      d_volume_iops     = 16000
      e_volume_size    = 16000 # E: 16TB (additional data volume)
      e_volume_throughput = 1000
      e_volume_iops     = 16000
      multithreading_enabled = false # PDF: hyperthreading disabled
    },
    {
      name           = "SRS001"
      subnet_id      = "subnet-PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Update with actual PRD subnet ID
      az             = "eu-west-2a"
      instance_type  = "r7i.xlarge" # PDF: Prd SSRS (2019) - 4 *hyper threading disabled, 32GB RAM
      server_function = "eweblogs-ssrs"
      server_type    = "db"
      ami_id         = "ami-PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Update with Windows Server 2019 AMI for PRD
      wsus_group     = "scan_only"
      wsus_qsid      = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group = "${local.wsus_policy_scan_only_name}"
      root_volume_size = 128 # PDF: OS disk 128GB
      # PDF shows PRD SSRS volumes: D: 1TB, L: 700GB
      d_volume_size    = 1000 # D: 1TB (data volume)
      d_volume_throughput = 250
      d_volume_iops     = 3000
      l_volume_size    = 700 # L: 700GB (logs volume)
      l_volume_throughput = 250
      l_volume_iops     = 3000
      multithreading_enabled = false # PDF: hyperthreading disabled
    }
  ]

  wsus_qsconfig_id_ring1      = "PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Get actual PRD WSUS config ID for ring 1
  wsus_qsconfig_id_ringscan   = "PLACEHOLDER_UPDATE_ME" # PLACEHOLDER: Get actual PRD WSUS config ID for scan only
  wsus_policy_scan_only_name  = "eweblogs_pol_wsus_scan_only" # PLACEHOLDER: Verify this PRD policy name exists

  ### Security Group Rules ###
  # PRD CIDR blocks - these will be different from DEV
  delinea_cidr_block     = ["100.88.4.0/25"] # PLACEHOLDER: Verify PRD Delinea CIDR
  ss_ad_cidr             = ["100.88.84.96/27"] # PLACEHOLDER: Verify PRD Shared Services AD CIDR
  wsus_cidr              = ["100.88.86.0/27"] # PLACEHOLDER: Verify PRD WSUS CIDR
  bastion_dba_cidr       = ["100.88.16.0/26"] # PLACEHOLDER: Verify PRD Bastion CIDR
  fsx_shares_cidr        = ["100.88.81.64/27"] # PLACEHOLDER: Verify PRD FSx CIDR
  hda_cidr               = ["100.88.88.0/28"] # PLACEHOLDER: Verify PRD HDA CIDR
  sentryone_app_cidr     = ["100.88.84.160/32", "100.88.84.137/32", "100.88.84.168/32", "100.88.84.166/32", "100.88.84.203/32", "100.88.84.215/32", "100.88.84.252/32", "100.88.84.205/32"] # PLACEHOLDER: Verify PRD SentryOne IPs
  eng_sql_subnet_cidr    = ["100.88.36.0/27", "100.88.40.0/21"] # PLACEHOLDER: Verify PRD England SQL subnets
  nat_sql_subnet_cidr    = ["100.88.132.0/22", "100.88.136.0/21"] # PLACEHOLDER: Verify PRD Nations SQL subnets
  ss_sql_subnet_cidr     = ["100.88.64.0/21", "100.88.72.0/22"] # PLACEHOLDER: Verify PRD Shared Services SQL subnets
  on_prem_sql_instance_cidr = ["172.16.0.0/16", "192.168.0.0/16", "44.0.0.0/8"] # PLACEHOLDER: Verify PRD on-prem ranges
  r53_outbound_endpoint_subnet = ["100.88.8.128/26"] # PLACEHOLDER: Verify PRD Route53 endpoint subnet
  hscn_dns              = ["155.231.231.1/32", "155.231.231.2/32"] # PLACEHOLDER: Verify PRD HSCN DNS IPs

  bastion_sg_rules_cidr_blocks = {
    rule1 = { type = "ingress", from = 3389, to = 3389, protocol = "tcp", cidr = local.delinea_cidr_block, desc = "Allow RDP in from Delinea Distributed Engine CIDR" }
  }

  sql_sg_rules_cidr_blocks = {
    rule1 = { type = "egress",  from = 445,  to = 445,  protocol = "tcp", cidr = local.fsx_shares_cidr,    desc = "allow 445 to fsx subnets" }
    rule2 = { type = "egress",  from = 5985, to = 5985, protocol = "tcp", cidr = local.fsx_shares_cidr,    desc = "allow 5985 to fsx subnets" }
    rule3 = { type = "egress",  from = 1433, to = 1433, protocol = "tcp", cidr = local.eng_sql_subnet_cidr, desc = "allow 1433 outbound to england sql subnets" }
    rule4 = { type = "egress",  from = 1433, to = 1433, protocol = "tcp", cidr = local.nat_sql_subnet_cidr, desc = "allow 1433 outbound to nations sql subnets" }
    rule5 = { type = "egress",  from = 1433, to = 1433, protocol = "tcp", cidr = local.ss_sql_subnet_cidr,  desc = "allow 1433 outbound to shared services sql subnets" }
    rule6 = { type = "egress",  from = 1433, to = 1433, protocol = "tcp", cidr = local.on_prem_sql_instance_cidr, desc = "allow 1433 outbound to on-prem sql instances" }
    rule7 = { type = "ingress", from = 1433, to = 1433, protocol = "tcp", cidr = local.hda_cidr,        desc = "Allow TCP 1433 inbound from HDA Subnets" }
    rule8 = { type = "ingress", from = 5985, to = 5986, protocol = "tcp", cidr = "${local.hda_cidr}",   desc = "Allow TCP 5985 to 5986 inbound from HDA Subnets" }
    rule9 = { type = "ingress", from = 1434, to = 1434, protocol = "udp", cidr = "${local.hda_cidr}",   desc = "Allow UDP 1434 inbound from HDA Subnets" }
    rule10 = { type = "ingress", from = 1433, to = 1433, protocol = "tcp", cidr = local.sentryone_app_cidr, desc = "Allow tcp 1433 inbound from SentryOne APP Tier" }
  }

  standard_sg_rules_cidr_blocks = {
    rule1 = { type = "ingress", from = 443,  to = 443,  protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow 443 inbound from VPC CIDR" }
    rule2 = { type = "ingress", from = 53,   to = 53,   protocol = "udp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow DNS in from VPC CIDR" }
    rule3 = { type = "ingress", from = 53,   to = 53,   protocol = "tcp", cidr = "${local.r53_outbound_endpoint_subnet}",   desc = "Allow DNS in from networks services route 53 resolver outbound endpoint subnet" }
    rule4 = { type = "ingress", from = 3389, to = 3389, protocol = "tcp", cidr = "${local.delinea_cidr_block}",         desc = "Allow RDP in from Delinea Distributed Engine CIDR" }
    rule5 = { type = "egress",  from = 53,   to = 53,   protocol = "udp", cidr = "${local.r53_outbound_endpoint_subnet}", desc = "Allow outbound to networks services route 53 resolver outbound endpoint subnet" }
    rule6 = { type = "egress",  from = 88,   to = 88,   protocol = "udp", cidr = "${local.ss_ad_cidr}",               desc = "Allow UDP 88 to Kerberos SS AD subnet" }
    rule7 = { type = "egress",  from = 88,   to = 88,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 88 to Kerberos SS AD subnet" }
    rule8 = { type = "egress",  from = 135,  to = 135,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 135 to RPC SS AD subnet" }
    rule9 = { type = "egress",  from = 139,  to = 139,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 139 to NetBios SS AD subnet" }
    rule10 = { type = "egress", from = 445,  to = 445,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 445 to SMB SS AD subnet" }
    rule11 = { type = "egress", from = 445,  to = 445,  protocol = "udp", cidr = "${local.ss_ad_cidr}",               desc = "Allow UDP 445 to SMB SS AD subnet" }
    rule12 = { type = "egress", from = 389,  to = 389,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 389 to LDAP SS AD subnet" }
    rule13 = { type = "egress", from = 389,  to = 389,  protocol = "udp", cidr = "${local.ss_ad_cidr}",               desc = "Allow UDP 389 to LDAP SS AD subnet" }
    rule14 = { type = "egress", from = 636,  to = 636,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP to LDAPS SS AD subnet" }
    rule15 = { type = "egress", from = 464,  to = 464,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP to AD SS AD subnet" }
    rule16 = { type = "egress", from = 3268, to = 3268, protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP to AD SS AD subnet" }
    rule17 = { type = "egress", from = 53,   to = 53,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP 53 to DNS SS AD subnet" }
    rule18 = { type = "egress", from = 53,   to = 53,   protocol = "udp", cidr = "${local.ss_ad_cidr}",               desc = "Allow UDP 53 to DNS SS AD subnet" }
    rule19 = { type = "egress", from = 636,  to = 636,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP LDAPS to DNS SS AD subnet" }
    rule20 = { type = "egress", from = 123,  to = 123,  protocol = "udp", cidr = "${local.ss_ad_cidr}",               desc = "Allow TCP NTP time sync to DNS SS AD subnet" }
    rule21 = { type = "egress", from = 5985, to = 5986, protocol = "tcp", cidr = "${local.bastion_dba_cidr}",         desc = "Allow TCP 5985 from Generic Bastion Subnets" }
    rule22 = { type = "egress", from = 135,  to = 135,  protocol = "tcp", cidr = "${local.bastion_dba_cidr}",         desc = "Allow TCP 135 from Generic Bastion Subnets" }
    rule23 = { type = "egress", from = 8530, to = 8531, protocol = "tcp", cidr = "${local.wsus_cidr}",                desc = "Allow TCP 8530 - 8531 to WSUS" }
    rule24 = { type = "egress", from = 53,   to = 53,   protocol = "udp", cidr = "${local.hscn_dns}",                 desc = "Allow DNS outbound udp to HSCN" }
    rule25 = { type = "egress", from = 53,   to = 53,   protocol = "tcp", cidr = "${local.hscn_dns}",                 desc = "Allow DNS outbound tcp to HSCN" }
    rule26 = { type = "egress", from = 5985, to = 5986, protocol = "tcp", cidr = local.ss_ad_cidr,                    desc = "allow 5985-5986 inbound from shared services m ad n" }
    rule27 = { type = "egress", from = 135,  to = 135,  protocol = "tcp", cidr = local.ss_ad_cidr,                    desc = "allow 135 inbound from shared services m ad subnet" }
    rule28 = { type = "egress", from = 0,    to = 65535, protocol = "udp", cidr = local.ss_ad_cidr,                   desc = "DC dynamic UDP ports from Shared Services MAD subnet" }
    rule29 = { type = "egress", from = 1690, to = 1690, protocol = "tcp", cidr = local.ss_ad_cidr,                    desc = "Allow TCP 1690 from Shared Services MAD subnet" }
    rule30 = { type = "egress", from = 49152, to = 65535, protocol = "tcp", cidr = local.ss_ad_cidr,                  desc = "Allow TCP Winrpmt from SS AD subnet" }
    rule31 = { type = "egress", from = 443,  to = 443,  protocol = "tcp", cidr = ["0.0.0.0/0"],                       desc = "Allow all egress https traffic" }
  }
}