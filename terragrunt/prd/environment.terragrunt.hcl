locals {
  common = read_terragrunt_config("${get_terragrunt_dir()}/../common.terragrunt.hcl")

  # Configure environment
  region             = get_env("AWS_REGION")
  account_id         = get_env("AWS_ACCOUNT_ID")
  environment        = get_env("ENVIRONMENT")
  service            = local.common.locals.service
  project_name       = "${local.environment}-${local.service}"
  region_prefix      = format("%s%s%s", substr("${local.region}", 0, 2), substr("${local.region}", 3, 1), substr("${local.region}", 8, 1))
  service_identifier = "${local.common.locals.service_location}"

### SFTP ###
  ssh_key = get_env("ssh_key")
  transfer_users = {
    test = {
      user_name      = "test"
      home_directory = "test"
      ssh_key        = local.ssh_key # This is a ssh key owned by IBI team to test client connection. A customer ssh key will be manaully added via the management console.
    }
  }

### VPC ###
  ipv4_primary_cidr_block       = "100.88.179.64/26" # UPDATE_ME
  sftp_ipv4_primary_cidr_block  = "100.88.179.32/27" # UPDATE_ME
  tgw_id_backbone               = "tgw-0f28603fcaf843cb9"

  intra_subnets = {
    sql = {
      sql-2a = {
        cidr_block           = "100.88.179.64/27" # UPDATE_ME
        availability_zone_id = "euw2-az2"
      }
    }
  }

  name = {
    environment = "${local.environment}"
    service     = "ibi"
    identifier  = "eweblogs"
  }

  route53_resolver_rules = {
    prd_england_emis_web_com = {
      rule_id = "rslvr-rr-80152c982c564b66b"
    }
    analytics1 = {
      rule_id = "rslvr-rr-a7fecadc99a427b9e"
    }
    ccmh = {
      rule_id = "rslvr-rr-94e332794c0e4b698"
    }
    gplive = {
      rule_id = "rslvr-rr-9034c75c4cf140de8"
    }
    white = {
      rule_id = "rslvr-rr-bc9a029abd864d828"
    }
    emishosting = {
      rule_id = "rslvr-rr-c991720e03ad4d56a"
    }
    emishome = {
      rule_id = "rslvr-rr-5f337ace7b014f3fb"
    }
    hscn_catch_all = {
      rule_id = "rslvr-rr-c233db4579f54d369"
    }
    shared_services = {
      rule_id = "rslvr-rr-2ca09cef339c4cedb"
    }
    hscni = {
      rule_id = "rslvr-rr-f871cf10594b4339a"
    }
    hscninet = {
      rule_id = "rslvr-rr-bbb34f8986634178b"
    }
    iom = {
      rule_id = "rslvr-rr-8b829e0e495440bf9"
    }
    jersey = {
      rule_id = "rslvr-rr-2900e554858743a6b"
    }
    cp = {
      rule_id = "rslvr-rr-3a698c3f20434754b"
    }
    prod_iom_emis_web_com = {
      rule_id = "rslvr-rr-1da8e8c0d7484cf79"
    }   
    prod_scotland_emis_web_com = {
      rule_id = "rslvr-rr-9ad8081235d246a5b"
    }
    prod_northernireland_emis_web_com = {
      rule_id = "rslvr-rr-efe83ae95304dafb8"
    }
    prod_jersey_emis_web_com = {
      rule_id = "rslvr-rr-f9f52acb83a441df8"
    }
    awshosted_emis-clinical_com = {
      rule_id = "rslvr-rr-1e7f598835214f529"
    }
  }

### KMS ###
  key_users        = [
    "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/${local.region}/AWSReservedSSO_cloudcustodians-power-user_43cb1a63abc024cc",
    "arn:aws:iam::${local.account_id}:role/${local.environment}-ibi-eweblogs-ec2-role",
    "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_eweblogs-ibi-prd-s3upload-pol_4829b7fb461b79ba"
    ]
  key_administrors = [
    "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/${local.region}/AWSReservedSSO_cloudcustodians-power-user_43cb1a63abc024cc"
    ]

### EC2 ###
  ec2_name_prefix    = "em"
  domain_credentials = try(get_env("DOMAIN_CREDENTIALS"),"")
  servers = [
    {
      name                    = "SIS001"
      subnet_id               = "subnet-00e15b8a1822f749b"
      az                      = "eu-west-2a"
      instance_type           = "r6i.4xlarge"
      server_function         = "ibi-ssis"
      server_type             = "db"
      ami_id                  = "ami-06eb09971f4a1acdb"
      wsus_group              = "scan_only"
      wsus_qsid               = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group       = "${local.wsus_policy_scan_only_name}"
      root_volume_size        = 128
      d_volume_size           = 5000
      d_volume_throughput     = 1000
      d_volume_iops           = 14000
      l_volume_size           = 800
      l_volume_throughput     = 1000
      l_volume_iops           = 14000
      t_volume_size           = 450
      t_volume_throughput     = 1000
      t_volume_iops           = 14000
      multithreading_enabled  = false
    },
    {
      name                    = "SAS001"
      subnet_id               = "subnet-00e15b8a1822f749b"
      az                      = "eu-west-2a"
      instance_type           = "r6i.4xlarge"
      server_function         = "ibi-ssas"
      server_type             = "db"
      ami_id                  = "ami-06eb09971f4a1acdb"
      wsus_group              = "scan_only"
      wsus_qsid               = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group       = "${local.wsus_policy_scan_only_name}"
      root_volume_size        = 128
      d_volume_size           = 750
      d_volume_throughput     = 1000
      d_volume_iops           = 14000
      multithreading_enabled  = false
    },
    {
      name                    = "SRS001"
      subnet_id               = "subnet-00e15b8a1822f749b"
      az                      = "eu-west-2a"
      instance_type           = "r6i.4xlarge"
      server_function         = "ibi-ssrs"
      server_type             = "db"
      ami_id                  = "ami-06eb09971f4a1acdb"
      wsus_group              = "scan_only"
      wsus_qsid               = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group       = "${local.wsus_policy_scan_only_name}"
      root_volume_size        = 128
      d_volume_size           = 750
      d_volume_throughput     = 1000
      d_volume_iops           = 14000
      multithreading_enabled  = false
    },
    {
      name                    = "MGT001"
      subnet_id               = "subnet-00e15b8a1822f749b"
      az                      = "eu-west-2a"
      instance_type           = "r6i.2xlarge"
      server_function         = "ibi-mgmt"
      server_type             = "db"
      ami_id                  = "ami-06eb09971f4a1acdb"
      wsus_group              = "scan_only"
      wsus_qsid               = "QSConfigName-${local.wsus_qsconfig_id_ringscan}"
      wsus_policy_group       = "${local.wsus_policy_scan_only_name}"
      root_volume_size        = 220
      e_volume_size           = 60
      multithreading_enabled  = false
    }
  ]

  wsus_qsconfig_id_ring1     = "qubhi"
  wsus_qsconfig_id_ringscan  = "85ycu"
  wsus_policy_scan_only_name = "ibi_ewbl_pol_scan_only"

### SGs ###
  delinea_cidr_block           = ["100.88.4.0/25"]
  ss_ad_cidr                   = ["100.88.84.96/27"]
  wsus_cidr                    = ["100.88.86.0/27"]
  bastion_generic_cidr         = ["100.88.16.0/26"]
  fsx_shares_cidr              = ["100.88.81.64/27"]
  hda_cidr                     = ["100.88.88.0/28"]
  sentryone_app_cidr           = ["100.88.84.140/32", "100.88.84.137/32", "100.88.84.168/32", "100.88.84.166/32", "100.88.84.203/32", "100.88.84.215/32", "100.88.84.252/32", "100.88.84.205/32"]
  eng_sql_subnet_cidr          = ["100.88.36.0/22", "100.88.40.0/21"]
  nat_sql_subnet_cidr          = ["100.88.132.0/22", "100.88.136.0/21"]
  ss_sql_subnet_cidr           = ["100.88.64.0/21", "100.88.72.0/22"]
  on_prem_sql_instance_cidr    = ["172.16.0.0/16", "192.168.0.0/16", "44.0.0.0/8"]
  r53_outbound_endpoint_subnet = ["100.88.8.128/26"]
  hscn_dns                     = ["155.231.231.1/32", "155.231.231.2/32"]
  emisnow_ips                  = ["148.139.13.160/32"]

  bastion_sg_rules_cidr_blocks = {
    rule1 = { type = "ingress", from = 3389, to = 3389, protocol = "tcp", cidr = local.delinea_cidr_block,     desc = "Allow RDP in from Delinea Distributed Engine CIDR" }
  }

  sql_sg_rules_cidr_blocks    = {
    rule1   = { type = "egress",  from = 445,   to = 445,   protocol = "tcp", cidr = local.fsx_shares_cidr,           desc = "allow 445 to fsx subnets" }
    rule2   = { type = "egress",  from = 5985,  to = 5985,  protocol = "tcp", cidr = local.fsx_shares_cidr,           desc = "allow 5985 to fsx subnets" }
    rule5   = { type = "egress",  from = 1433,  to = 1433,  protocol = "tcp", cidr = local.eng_sql_subnet_cidr,       desc = "allow 1433 outbound to england sql subnets" }
    rule6   = { type = "egress",  from = 1433,  to = 1433,  protocol = "tcp", cidr = local.nat_sql_subnet_cidr,       desc = "allow 1433 outbound to nations sql subnets" }
    rule7   = { type = "egress",  from = 1433,  to = 1433,  protocol = "tcp", cidr = local.ss_sql_subnet_cidr,        desc = "allow 1433 outbound to shared services sql subnets" }
    rule8   = { type = "egress",  from = 1433,  to = 1433,  protocol = "tcp", cidr = local.on_prem_sql_instance_cidr, desc = "allow 1433 outbound to on-prem sql instances" }
    rule11  = { type = "ingress", from = 1433,  to = 1433,  protocol = "tcp", cidr = "${local.hda_cidr}",             desc = "Allow TCP 1433 inbound from HDA Subnets" }
    rule12  = { type = "ingress", from = 5985,  to = 5986,  protocol = "tcp", cidr = "${local.hda_cidr}",             desc = "Allow TCP 5985 to 5986 inbound from HDA Subnets" }
    rule13  = { type = "ingress", from = 1434,  to = 1434,  protocol = "udp", cidr = "${local.hda_cidr}",             desc = "Allow UDP 1434 inbound from HDA Subnets" }
    rule14  = { type = "ingress", from = 1433,  to = 1433,  protocol = "tcp", cidr = local.sentryone_app_cidr,        desc = "Allow tcp 1433 inbound from SentryOne APP Tier" }
    rule15  = { type = "egress",  from = 3128,  to = 3128,  protocol = "tcp", cidr = local.emisnow_ips,               desc = "Allow tcp 3128 outbound to EMISNow" }
  }

  standard_sg_rules_cidr_blocks = {
    rule1  = { type = "ingress", from = 443,   to = 443,   protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "allow 443 inbound from VPC CIDR" }
    rule2  = { type = "ingress", from = 53,    to = 53,    protocol = "udp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow DNS in from VPC CIDR" }
    rule3  = { type = "ingress", from = 53,    to = 53,    protocol = "udp", cidr = "${local.r53_outbound_endpoint_subnet}",      desc = "Allow DNS in from networks services route 53 resolver endpoint" }
    rule4  = { type = "ingress", from = 3389,  to = 3389,  protocol = "tcp", cidr = "${local.delinea_cidr_block}",                desc = "Allow RDP in from Delinea Distributed Engine CIDR" }
    rule5  = { type = "egress",  from = 53,    to = 53,    protocol = "udp", cidr = "${local.r53_outbound_endpoint_subnet}",      desc = "Allow DNS outbound to networks services route 53 resolver endpoint" }
    rule6  = { type = "egress",  from = 88,    to = 88 ,   protocol = "udp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow UDP 88 to Kerberos SS AD subnet" }
    rule7  = { type = "egress",  from = 88,    to = 88 ,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 88 to Kerberos SS AD subnet" }
    rule8  = { type = "egress",  from = 135,   to = 135,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 135 to RPC SS AD subnet" }
    rule9  = { type = "egress",  from = 139,   to = 139,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 139 to NetBios SS AD subnet" }
    rule10 = { type = "egress",  from = 445,   to = 445,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 445 to SMB SS AD subnet" }
    rule11 = { type = "egress",  from = 445,   to = 445,   protocol = "udp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow UDP 445 to SMB SS AD subnet" }
    rule12 = { type = "egress",  from = 389,  to = 389,    protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 389 to LDAP SS AD subnet" }
    rule13 = { type = "egress",  from = 389,  to = 389,    protocol = "udp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow UDP 389 to LDAP SS AD subnet" }
    rule14 = { type = "egress",  from = 49152, to = 65535, protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP to apps SS AD subnet" }
    rule15 = { type = "egress",  from = 464,   to = 464,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP to AD SS AD subnet" }
    rule16 = { type = "egress",  from = 3268,  to = 3269,  protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP to AD SS AD subnet" }
    rule17 = { type = "egress",  from = 53,    to = 53,    protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP 53 to DNS SS AD subnet" }
    rule18 = { type = "egress",  from = 53,    to = 53,    protocol = "UDP", cidr = "${local.ss_ad_cidr}",                        desc = "Allow UDP 53 to DNS SS AD subnet" }
    rule19 = { type = "egress",  from = 636,   to = 636,   protocol = "tcp", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP ldaps to DNS SS AD subnet" }
    rule20 = { type = "egress",  from = 123,   to = 123,   protocol = "UDP", cidr = "${local.ss_ad_cidr}",                        desc = "Allow TCP NTP time sync to DNS SS AD subnet" }
    rule21 = { type = "ingress", from = 5985,  to = 5986,  protocol = "tcp", cidr = "${local.bastion_generic_cidr}",              desc = "Allow TCP 5985 from Generic Bastion Subnets" }
    rule22 = { type = "ingress", from = 135,   to = 135,   protocol = "tcp", cidr = "${local.bastion_generic_cidr}",              desc = "Allow TCP 135 from Generic Bastion Subnets" }
    rule23 = { type = "egress",  from = 8530,  to = 8531,  protocol = "tcp", cidr = "${local.wsus_cidr}",                         desc = "Allow TCP 8530 - 8531 to WSUS" }
    rule24 = { type = "egress",  from = 53,    to = 53,    protocol = "udp", cidr = "${local.hscn_dns}",                          desc = "Allow DNS outbound udp to HSCN" }
    rule25 = { type = "egress",  from = 53,    to = 53,    protocol = "tcp", cidr = "${local.hscn_dns}",                          desc = "Allow DNS outbound tcp to HSCN" }  
    rule26 = { type = "ingress", from = 5985,  to = 5986,  protocol = "tcp", cidr = local.ss_ad_cidr,                             desc = "allow 5985-5986 inbound from shared services m-ad subnets" }
    rule27 = { type = "ingress", from = 135,   to = 135,   protocol = "tcp", cidr = local.ss_ad_cidr,                             desc = "allow 135 inbound from shared services m-ad subnets" }
    rule28 = { type = "ingress", from = 0,     to = 65535, protocol = "udp", cidr = local.ss_ad_cidr,                             desc = "SQL dynamic UDP ports from Shared Services MAD subnets" }
    rule29 = { type = "ingress", from = 1430,  to = 1440,  protocol = "tcp", cidr = local.ss_ad_cidr,                             desc = "SQL standard ports from Shared Services MAD subnets" }
    rule30 = { type = "ingress", from = 49152, to = 65535, protocol = "tcp", cidr = local.ss_ad_cidr,                             desc = "Allow TCP Winmgmt from SS AD subnet" }
    rule31 = { type = "egress",  from = 443,   to = 443,   protocol = "tcp", cidr = ["0.0.0.0/0"],                                desc = "Allow all egress https traffic" }
    rule32 = { type = "ingress", from = 135,   to = 135,   protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 135 in from VPC CIDR" }
    rule33 = { type = "egress",  from = 135,   to = 135,   protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 135 out from VPC CIDR" }
    rule34 = { type = "ingress", from = 1433,  to = 1433,  protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 1433 in from VPC CIDR" }
    rule35 = { type = "egress",  from = 1433,  to = 1433,  protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 1433 out from VPC CIDR" }
    rule36 = { type = "ingress", from = 2383,  to = 2383,  protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 2383 in from VPC CIDR" }
    rule37 = { type = "egress",  from = 2383,  to = 2383,  protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 2383 out from VPC CIDR" }
    rule38 = { type = "ingress", from = 1434,  to = 1434,  protocol = "udp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow UDP 1434 in from VPC CIDR" }
    rule39 = { type = "egress",  from = 1434,  to = 1434,  protocol = "udp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow UDP 1434 out from VPC CIDR" }
    rule40 = { type = "ingress", from = 445,   to = 445,   protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 445 in from VPC CIDR" }
    rule41 = { type = "egress",  from = 445,   to = 445,   protocol = "tcp", cidr = concat(["${local.ipv4_primary_cidr_block}"]), desc = "Allow TCP 445 out from VPC CIDR" }
  }

}
