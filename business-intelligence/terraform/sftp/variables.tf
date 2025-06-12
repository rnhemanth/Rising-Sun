variable "service" {
  description = "The name of the service"
  type        = string
  default     = "ibi-sftp"
}

variable "environment" {
  type        = string
  description = "Name of the deployment environmnet. e.g. sbx, dev, stg, prd"
  validation {
    condition     = contains(["sbx", "dev", "stg", "prd"], var.environment)
    error_message = "environment value must be sbx, dev, stg or prd."
  }
}

variable "sftp_ipv4_primary_cidr_block" {
  type = string
  description = "CIDR block for the SFTP VPC"
}

variable "ipv4_primary_cidr_block" {
  type = string
  description = "CIDR block for the SIBI VPC"
}

variable "transfer_users" {
  description = "A map of transfer users to create"
  type        = string
  default     = "{}"
}

variable "region" {
  type        = string
  default     = "eu-west-2"
  description = "AWS Region"
}

variable "ssh_key" {
  description = "default SSH key to be used for SFTP"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "A map of tags to add to IAM role resources"
  type        = map(string)
  default     = {}
}

variable "key_owners" {
  description = "A list of IAM ARNs for those who will have full key permissions (`kms:*`)"
  type        = list(string)
  default     = []
}

variable "key_administrators" {
  description = "A list of IAM ARNs for [key administrators](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-administrators)"
  type        = list(string)
  default     = []
}

variable "key_users" {
  description = "A list of IAM ARNs for [key users](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-users)"
  type        = list(string)
  default     = []
}

variable "key_service_users" {
  description = "A list of IAM ARNs for [key service users](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-service-integration)"
  type        = list(string)
  default     = []
}