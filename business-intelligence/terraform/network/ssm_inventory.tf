resource "aws_ssm_resource_data_sync" "finops_ssm_inventory_data_sync" {
  name = "finops-ssm-inventory-data-sync"
  s3_destination {
    bucket_name = var.s3_destination.bucket_name
    region      = var.s3_destination.region
    sync_format = var.s3_destination.sync_format
  }
}

resource "aws_ssm_association" "finops_sql_inventory" {
  count = var.create_finops_sql_inventory_ssm_association ? 1 : 0

  association_name                = "finops-sql-inventory"
  name                           = "AWS-GatherSoftwareInventory"
  schedule_expression            = var.sql_inventory_schedule_expression
  apply_only_at_cron_interval    = var.sql_inventory_apply_only_at_cron_interval

  parameters = {
    billingInfo                    = var.sql_inventory_parameters.billingInfo
    windowsHotfixes                = var.sql_inventory_parameters.windowsHotfixes
    networkConfig                  = var.sql_inventory_parameters.networkConfig
    windowsUpdates                 = var.sql_inventory_parameters.windowsUpdates
    customInventory                = var.sql_inventory_parameters.customInventory
    instanceDetailedInformation    = var.sql_inventory_parameters.instanceDetailedInformation
    windowsRegistry                = var.sql_inventory_parameters.windowsRegistry
    services                       = var.sql_inventory_parameters.services
    applications                   = var.sql_inventory_parameters.applications
    awsComponents                  = var.sql_inventory_parameters.awsComponents
  }

  targets {
    key    = var.sql_inventory_targets.key
    values = var.sql_inventory_targets.values
  }
}

resource "aws_ssm_association" "finops_sql_registry_key_creator" {
  count = var.create_finops_sql_registry_key_creator_ssm_association ? 1 : 0

  association_name                = "finops-sql-registry-key-creator"
  name                           = "AWS-RunPowerShellScript"
  schedule_expression            = var.sql_registry_key_creator_schedule_expression
  apply_only_at_cron_interval    = var.sql_registry_key_creator_apply_only_at_cron_interval
  compliance_severity            = var.sql_registry_key_creator_compliance_severity

  parameters = {
    executionTimeout = var.sql_registry_key_creator_execution_timeout
    commands = <<-EOF
      # Get SQL Server instance names from registry
      $instancePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
      $instances = Get-ItemProperty -Path $instancePath

      # Initialize counter
      $instanceCount = 0
      $maxinstances = 3

      # Loop through instances (limited to 3)
      foreach ($instance in $instances.PSObject.Properties) {
        # Skip properties that aren't instances
        if ($instance.Name -eq "PSPath" -or $instance.Name -eq "PSParentPath" -or
            $instance.Name -eq "PSChildName" -or $instance.Name -eq "PSProvider") {
          continue
        }

        # Break if we've processed 3 instances
        if ($instanceCount -ge $maxinstances) {
          break
        }

        $instanceName = $instance.Name
        $instanceValue = $instance.Value
        # Build the registry path for this instance
        $sqlRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceValue\Setup"
        Write-Host "Processing instance: $instanceName ($instanceValue)"
        # Get MSSQL Registry keys for the instance
        try {
          $edition = Get-ItemPropertyValue $sqlRegistryPath 'Edition'
          $version = Get-ItemPropertyValue $sqlRegistryPath 'Version'
          # Create inventory entry with individual keys
          $inventoryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\LEWIS_INVENTORY"
          
          # Create new registry key if it doesn't exist
          if (-not (Test-Path $inventoryPath)) {
            New-Item -Path $inventoryPath -Force | Out-Null
          }
          # Create properties based on instance count
          if ($instanceCount -eq 0) {
            # First instance - use numbered property names
            New-ItemProperty -Path $inventoryPath `
              -Name "Instance" `
              -Value $instanceName `
              -PropertyType "String" -Force | Out-Null
            New-ItemProperty -Path $inventoryPath `
              -Name "Version" `
              -Value $version `
              -PropertyType "String" -Force | Out-Null
            New-ItemProperty -Path $inventoryPath `
              -Name "Edition" `
              -Value $edition `
              -PropertyType "String" -Force | Out-Null
          }
          else {
            # Subsequent instances - use numbered property names
            $propertyNumber = $instanceCount + 1
            New-ItemProperty -Path $inventoryPath `
              -Name "Instance$propertyNumber" `
              -Value $instanceName `
              -PropertyType "String" -Force | Out-Null
            New-ItemProperty -Path $inventoryPath `
              -Name "Version$propertyNumber" `
              -Value $version `
              -PropertyType "String" -Force | Out-Null
            New-ItemProperty -Path $inventoryPath `
              -Name "Edition$propertyNumber" `
              -Value $edition `
              -PropertyType "String" -Force | Out-Null
          }
          Write-Host "Successfully processed instance $instanceName"
          $instanceCount++
        }
        catch {
          Write-Warning "Failed to process instance $instanceName : $_"
          continue
        }
      }

      # Add count of processed instances
      New-ItemProperty -Path $inventoryPath `
        -Name "InstanceCount" `
        -Value $instanceCount `
        -PropertyType "DWORD" -Force | Out-Null

      Write-Host "Successfully created inventory with $instanceCount instance(s)"
    EOF
  }

  targets {
    key    = var.sql_registry_key_creator_targets.key
    values = var.sql_registry_key_creator_targets.values
  }
}

variable "sql_registry_key_creator_schedule_expression" {
  description = "The schedule expression for the sql registry key creator SSM association"
  type        = string
  default     = "cron(0 09 12 ? * *)"
}

variable "sql_registry_key_creator_apply_only_at_cron_interval" {
  description = "Apply only at cron interval for the sql registry key creator SSM association"
  type        = bool
  default     = true
}

variable "sql_registry_key_creator_compliance_severity" {
  description = "The compliance severity for the sql registry key creator SSM association"
  type        = string
  default     = "UNSPECIFIED"
}

variable "sql_registry_key_creator_execution_timeout" {
  description = "sql registry key creator SSM association execution timeout"
  type        = string
  default     = "3600"
}

variable "sql_registry_key_creator_targets" {
  description = "The targets for the sql registry key creator SSM association"
  type = object({
    key    = string
    values = list(string)
  })
  default = {
    key    = "tag:server_type"
    values = ["db", "DB", "CCH-TRM-onebox", "CCH-UAT-onebox", "CCH-LAD-onebox"]
  }
}

variable "sql_inventory_parameters" {
  description = "The parameters for the SSM association"
  type = object({
    billingInfo                    = string
    windowsHotfixes                = string
    networkConfig                  = string
    windowsUpdates                 = string
    customInventory                = string
    instanceDetailedInformation    = string
    windowsRegistry                = string
    services                       = string
    applications                   = string
    awsComponents                  = string
  })
  default = {
    billingInfo                    = "Disabled"
    windowsHotfixes                = "Disabled"
    networkConfig                  = "Disabled"
    windowsUpdates                 = "Disabled"
    customInventory                = "Disabled"
    instanceDetailedInformation    = "Enabled"
    windowsRegistry                = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\LEWIS_INVENTORY\\*, Recursive=false, ValueNames=\\*, Edit=Edition\\]\\, \\Patch\\*\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\LEWIS_INVENTORY\\*, Recursive=false, ValueNames=\\*, Edit=Version\\]\\, \\Patch\\*\\HKEY_LOCAL_MACHINE"
    services                       = "Disabled"
    applications                   = "Enabled"
    awsComponents                  = "Disabled"
  }
}

variable "sql_inventory_apply_only_at_cron_interval" {
  description = "Apply only at cron interval for the sql inventory SSM association"
  type        = bool
  default     = false
}

variable "sql_inventory_schedule_expression" {
  description = "The schedule expression for the sql inventory SSM association"
  type        = string
  default     = "cron(0 09 14 ? * *)"
}

variable "sql_inventory_targets" {
  description = "The targets for the sql inventory SSM association"
  type = object({
    key    = string
    values = list(string)
  })
  default = {
    key    = "tag:server_type"
    values = ["db", "DB", "CCH-TRM-onebox", "CCH-UAT-onebox", "CCH-LAD-onebox"]
  }
}

variable "s3_destination" {
  description = "The S3 destination configuration for data sync"
  type = object({
    bucket_name = string
    region      = string
    sync_format = string
  })
  default = {
    bucket_name = "ssm-finops-data-sync-inv"
    region      = "eu-west-2"
    sync_format = "JsonSerDe"
  }
}

variable "create_finops_sql_inventory_ssm_association" {
  description = "Create the sql inventory SSM association"
  default     = true
  type        = bool
}

variable "create_finops_sql_registry_key_creator_ssm_association" {
  description = "Create the sql registry key creator SSM association"
  default     = true
  type        = bool
}

variable "create_finops_ssm_inventory_data_sync" {
  description = "Create ssm inventory data sync"
  default     = true
  type        = bool
}