terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

############################
# Variables
############################
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Name prefix for resources"
  type        = string
  default     = "aap-single"
}

variable "instance_type" {
  description = "Instance type for all-in-one host"
  type        = string
  default     = "m6i.2xlarge"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR"
  type        = string
  default     = "10.42.10.0/24"
}

variable "ssh_public_key" {
  description = "Your SSH public key content (e.g., from id_ed25519.pub)"
  type        = string
}

# AMI pinned as requested
variable "ami_id" {
  description = "RHEL 9 BYOS/Access AMI ID"
  type        = string
  default     = "ami-07af684733f156701"
}

variable "admin_password" {
  description = "Admin password for AAP components"
  type        = string
  default     = "ChangeMe_Strong!123"
  sensitive   = true
}

variable "allow_ssh_from_cidr" {
  description = "CIDR allowed to SSH (22) into instances"
  type        = string
  default     = "0.0.0.0/0"
}

variable "allow_http_from_cidr" {
  description = "CIDR allowed to 80/443"
  type        = string
  default     = "0.0.0.0/0"
}

############################
# Availability Zone (use AZ IDs)
############################
data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

############################
# Locals
############################
locals {
  az_id_a = data.aws_availability_zones.available.zone_ids[0]

  volumes = {
    aap = 200
  }

  base_cloud_config = <<EOC
#cloud-config
hostname: aap.local
manage_etc_hosts: true
write_files:
  - path: /etc/profile.d/aap_umask.sh
    permissions: '0644'
    owner: root:root
    content: |
      umask 0022
runcmd:
  - sh -c "echo 'umask 0022' >> /etc/bashrc"
EOC
}

############################
# Networking
############################
resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone_id    = local.az_id_a
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route" "public_inet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

############################
# Security Group
############################
resource "aws_security_group" "aap" {
  name        = "${var.project}-sg"
  description = "AAP all-in-one SG"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allow_ssh_from_cidr]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allow_http_from_cidr]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allow_http_from_cidr]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-sg"
  }
}

############################
# Key Pair
############################
resource "aws_key_pair" "kp" {
  key_name   = "${var.project}-kp"
  public_key = var.ssh_public_key
  tags = {
    Name = "${var.project}-kp"
  }
}

############################
# Single EC2 (all-in-one)
############################
resource "aws_instance" "aap" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.aap.id]
  key_name                    = aws_key_pair.kp.key_name
  associate_public_ip_address = true

  user_data = local.base_cloud_config

  root_block_device {
    volume_size = local.volumes.aap
    volume_type = "gp3"
    iops        = 3000
    throughput  = 125
  }

  tags = {
    Name = "${var.project}-aap"
    Role = "aap-all-in-one"
  }
}

############################
# Generated AAP Inventory (local)
############################
resource "local_file" "inventory" {
  filename = "${path.module}/inventory.ini"
  content  = <<EOT
[aap]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[automationgateway]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[automationcontroller]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[automationhub]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[automationedacontroller]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[database]
${aws_instance.aap.public_ip} ansible_user=ec2-user

[all:vars]
admin_password='${var.admin_password}'
redis_mode=standalone

# Controller DB on localhost
pg_host='127.0.0.1'
pg_port=5432
pg_database='awx'
pg_username='awx'
pg_password='${var.admin_password}'
pg_sslmode='prefer'

# Hub DB on localhost
automationhub_admin_password='${var.admin_password}'
automationhub_pg_host='127.0.0.1'
automationhub_pg_port=5432
automationhub_pg_database='automationhub'
automationhub_pg_username='automationhub'
automationhub_pg_password='${var.admin_password}'
automationhub_pg_sslmode='prefer'

# EDA DB on localhost
automationedacontroller_admin_password='${var.admin_password}'
automationedacontroller_pg_host='127.0.0.1'
automationedacontroller_pg_port=5432
automationedacontroller_pg_database='automationedacontroller'
automationedacontroller_pg_username='automationedacontroller'
automationedacontroller_pg_password='${var.admin_password}'

# Optional URLs (use the instance public IP)
automationgateway_main_url='http://${aws_instance.aap.public_ip}'
EOT
}

############################
# Outputs
############################
output "aap_public_ip" {
  value = aws_instance.aap.public_ip
}

output "aap_ssh" {
  value = format("ssh -i ~/.ssh/id_ed25519 ec2-user@%s", aws_instance.aap.public_ip)
}

output "aap_url" {
  value = format("http://%s", aws_instance.aap.public_ip)
}