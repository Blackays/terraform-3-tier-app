variable "company" {
  type        = string
  description = "Company's namy"
  default     = "test"
}
variable "project_name" {
  type        = string
  description = "Project name"
  default     = "test"
}

variable "region" {
  type        = string
  description = "AWS Region of our project"
  default     = "us-west-2"
}
variable "aws_availability_zones_state" {
  type = string
  default = "available"
}
variable "vpc_cidr_block" {
  type        = string
  description = "VPC CIDR block"
  default     = "10.0.0.0/16"
}
variable "vpc_subnet_public_count" {
  type        = number
  description = "VPC CIDR public block"
  default     = 2
}
variable "vpc_subnet_private_count" {
  type        = number
  description = "VPC CIDR private block"
  default     = 2
}
variable "vpc_subnet_database_count" {
  type        = number
  description = "VPC CIDR public block"
  default     = 2
}
variable "client_cidr_block" {
  type        = string
  description = "Client CIDR Block for SSH"
  default     = "0.0.0.0/0"
}
variable "db_multi_az" {
  type        = bool
  description = "Create database subnet group for Multi-AZ"
  default     = false
}
variable "instance_type" {
  type        = string
  description = "EC2 Instance type"
  default     = "t2.micro"
}
variable "instance_count_desired" {
  type        = number
  description = "EC2 Instance count desired"
  default     = 2
}
variable "instance_count_minimum" {
  type        = number
  description = "EC2 Instance count minimum"
  default     = 1
}
variable "instance_count_maximum" {
  type        = number
  description = "EC2 Instance count maximum"
  default     = 2
}
variable "subnet_mask" {
  type        = number
  description = "VPC Subnet Mask"
  default     = 8
}
variable "create_igw" {
  type        = bool
  description = "Create Internet Gateway in VPC"
  default     = true
}
variable "create_database_subnet_group" {
  type        = bool
  description = "Create DB Subnet Group"
  default     = true
}
variable "enable_nat_gateway" {
  type        = bool
  description = "Enable NAT Gateway in VPC"
  default     = true
}
variable "single_nat_gateway" {
  type        = bool
  description = "Create single NAT Gateway"
  default     = true
}
variable "one_nat_gateway_per_az" {
  type        = bool
  description = "Create 1 NAT Gateway per AZ"
  default     = false
}
variable "db_engine" {
  type        = string
  description = "DB Engine"
  default     = "postgres"
}
variable "db_engine_version" {
  type        = string
  description = "DB Engine Version"
}
variable "db_instance_class" {
  type        = string
  description = "DB Instance class"
  default     = "db.t3.micro"
}
variable "db_port" {
  type        = number
  description = "DB Port"
  default     = 5432
}
variable "db_family" {
  type        = string
  description = "DB Family"
  default     = "postgres13"
}
variable "db_allocated_storage" {
  type        = number
  description = "DB Allocated Storage in GiB"
  default     = 5
}
variable "db_backup_retention_period" {
  type = number
  description = "Backup Retention Period"
  default = 1
}
variable "db_skip_final_snapshot" {
  type = bool
  default = true
}
variable "db_deletion_protection" {
  type = bool
  default = false
}
variable "db_create_monitoring_role" {
  type = bool
  default = true
}
variable "db_performance_insights_enabled" {
  type = bool
  default = true
}
variable "db_performance_insights_retention_period" {
  type = number
  default = 7
}
variable "db_monitoring_interval" {
  type = number
  default = 60
}
variable "db_password_length" {
  type = number
  default = 16
}
variable "db_name" {
  type = string
}
variable "db_username" {
  type = string
}
variable "asg_force_delete" {
  type        = bool
  description = "Auto Scaling Group Force Delete"
  default     = true
}
variable "asg_image_id" {
  type        = string
  description = "AMI Image ID for ASG"
  default     = "ami-098e42ae54c764c35"
}
variable "asg_cpu_high_scaling" {
  type = string
  default = "1"
}
variable "asg_cpu_low_scaling" {
  type = string
  default = "-1"
}
variable "asg_cpu_high_cooldown" {
  type = string
  default = "300"
}
variable "asg_cpu_low_cooldown" {
  type = string
  default = "300"
}
variable "asg_cpu_high_alarm_threshold" {
  type = string
  default = "80"
}
variable "asg_cpu_low_alarm_threshold" {
  type = string
  default = "10"
}