#### Provider configuration
provider "aws" {
  region = var.region

}

#### Backend S3 configuration
# 1. Create manually S3 bucket for terraform state
# 2. Create a DynamoDB table manually for state locking
# https://www.terraform.io/language/settings/backends/s3

terraform {
  backend "s3" {
    bucket         = "developmentgeoxstatebucket"
    key            = "terraform.tfstate"
    region         = var.region
    dynamodb_table = "developmentgeoxstatebucket"
  }
}

data "aws_availability_zones" "available" {
  state = var.aws_availability_zones_state
}

############################################################################################################################ VPC configuration (community module call)
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = lower("${var.project_name}")
  cidr = var.vpc_cidr_block
  azs  = data.aws_availability_zones.available.names[*]

  private_subnets  = [for subnet in range(var.vpc_subnet_private_count) : cidrsubnet(var.vpc_cidr_block, var.subnet_mask, subnet)]
  public_subnets   = [for subnet in range(var.vpc_subnet_public_count) : cidrsubnet(var.vpc_cidr_block, var.subnet_mask, subnet + 85)]
  database_subnets = [for subnet in range(var.vpc_subnet_database_count) : cidrsubnet(var.vpc_cidr_block, var.subnet_mask, subnet + 180)]

  enable_nat_gateway     = var.enable_nat_gateway
  single_nat_gateway     = var.single_nat_gateway
  one_nat_gateway_per_az = var.one_nat_gateway_per_az

  create_igw                   = var.create_igw
  create_database_subnet_group = var.create_database_subnet_group
  default_route_table_routes = [
    {
      cidr_block = "0.0.0.0/0"
      gateway_id = module.vpc.igw_id
    }
  ]

  tags = local.common_tags
}

############################################################################################################################# RDS configuration (community module call)
resource "random_password" "password" {
  length           = var.db_password_length
  special          = true
  override_special = "_%*"
}
data "aws_rds_engine_version" "rds_engine_version" {
  engine = var.db_engine
}

module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 3.0"

  identifier = lower("${var.project_name}")

  # All available versions: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html#PostgreSQL.Concepts
  engine         = var.db_engine
  engine_version = var.db_engine_version == null ? data.aws_rds_engine_version.rds_engine_version.version : var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  family            = var.db_family == "" ? data.aws_rds_engine_version.rds_engine_version.parameter_group_family : var.db_family
  name              = var.db_name == "" ? "${var.db_engine}_db" : var.db_name
  username          = var.db_username == "" ? "${var.project_name}_db" : var.db_username
  password          = random_password.password.result
  port              = var.db_port

  multi_az               = var.db_multi_az
  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [module.vpc.default_security_group_id]
  subnet_ids             = module.vpc.database_subnets
  create_db_subnet_group = false

  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  backup_retention_period = var.db_backup_retention_period
  skip_final_snapshot     = var.db_skip_final_snapshot
  deletion_protection     = var.db_deletion_protection

  performance_insights_enabled          = var.db_performance_insights_enabled
  performance_insights_retention_period = var.db_performance_insights_retention_period
  create_monitoring_role                = var.db_create_monitoring_role
  monitoring_interval                   = var.db_monitoring_interval
  monitoring_role_name                  = "${var.project_name}-monitoring-role"
  monitoring_role_description           = "Description for monitoring role"

}
resource "aws_security_group" "rds" {
  name        = "${var.db_engine}-allow"
  description = "allow connection to the ${var.db_engine}"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = var.db_engine
    security_groups = ["${module.vpc.default_security_group_id}"]
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

########################################################################################################################EC2 autoscaling group (community module call)

resource "aws_launch_template" "launch_template" {
  name_prefix   = var.project_name
  image_id      = var.asg_image_id
  instance_type = var.instance_type
}

resource "aws_autoscaling_group" "asg" {
  depends_on                = [aws_launch_template.launch_template]
  desired_capacity          = var.instance_count_desired
  max_size                  = var.instance_count_maximum
  min_size                  = var.instance_count_minimum
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = var.asg_force_delete
  vpc_zone_identifier       = module.vpc.private_subnets

  launch_template {
    id      = aws_launch_template.launch_template.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_attachment" "asg_attachment" {
  autoscaling_group_name = aws_autoscaling_group.asg.name
  alb_target_group_arn   = module.alb.target_group_arns[0]
}
#------------------------------------------------------------------------------
# AUTOSCALING POLICIES
#------------------------------------------------------------------------------
# Scaling UP - CPU High
resource "aws_autoscaling_policy" "cpu_high" {
  name                   = "${var.project_name}-cpu-high"
  autoscaling_group_name = aws_autoscaling_group.asg.name
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = var.asg_cpu_high_scaling
  cooldown               = var.asg_cpu_high_cooldown
}
# Scaling DOWN - CPU Low
resource "aws_autoscaling_policy" "cpu_low" {
  name                   = "${var.project_name}-cpu-high"
  autoscaling_group_name = aws_autoscaling_group.asg.name
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = var.asg_cpu_low_scaling
  cooldown               = var.asg_cpu_low_cooldown
}

#------------------------------------------------------------------------------
# CLOUDWATCH METRIC ALARMS
#------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "cpu_high_alarm" {
  alarm_name          = "${var.project_name}-cpu-high-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.asg_cpu_high_alarm_threshold
  actions_enabled     = true
  alarm_actions       = ["${aws_autoscaling_policy.cpu_high.arn}"]
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.asg.name}"
  }
}
resource "aws_cloudwatch_metric_alarm" "cpu_low_alarm" {
  alarm_name          = "${var.project_name}-cpu-low-alarm"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.asg_cpu_low_alarm_threshold
  actions_enabled     = true
  alarm_actions       = ["${aws_autoscaling_policy.cpu_low.arn}"]
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.asg.name}"
  }
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  name = "${var.project_name}-alb"

  vpc_id          = module.vpc.vpc_id
  security_groups = [aws_security_group.alb_security_group.id]
  subnets         = module.vpc.private_subnets

  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      target_group_index = 0
      action_type        = "forward"
    }
  ]

  target_groups = [
    {
      name             = "${var.project_name}-lb-tg"
      backend_port     = 80
      backend_protocol = "HTTP"
      vpc_id           = module.vpc.vpc_id
      target_type      = "instance"
    }
  ]
}

# #####################  ALB SG
resource "aws_security_group" "alb_security_group" {
  name        = "${var.project_name}-load-balancer-sg"
  description = "${var.project_name} Load Balancer Security Groups"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    
    protocol    = "-1"
    cidr_blocks = ["0.0.0-.0/0"]
  }
}
resource "aws_security_group_rule" "opened_https_to_alb" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb_security_group.id
}

#####################  ASG SG
resource "aws_security_group" "asg_sg" {
  name        = "${var.project_name}-asg"
  description = "Allow HTTP/HTTPS to ${var.project_name} ASG"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.common_tags
}
resource "aws_security_group_rule" "allow_http_to_asg" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.asg_sg.id
}
resource "aws_security_g-roup_rule" "opened_asg_to_alb" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.asg_sg.id
}

#################################################################################################################################### VPN Configuration
# data "aws_secretsmanager_secret" "saml" {
#   name = "saml_metadata"
# }

# data "aws_secretsmanager_secret_version" "saml" {
#   secret_id     = data.aws_secretsmanager_secret.saml.id
#   version_stage = "AWSCURRENT"
# }

# resource "aws_iam_saml_provider" "vpn" {
#   name                   = var.vpn_saml_provider_name # could be anything that satisfy regular expression pattern: [\w._-]+ 
#   saml_metadata_document = base64decode(jsondecode(data.aws_secretsmanager_secret_version.saml.secret_string)["saml_metadata_xml"]) # saml_metadata_xml
#   tags                   = var.tags
# }

module "vpn" {
  source                     = "fivexl/client-vpn-endpoint/aws"
  endpoint_name              = "GeoXvpn"
  endpoint_client_cidr_block = "10.100.0.0/16"
  endpoint_subnets           = [module.vpc.intra_subnets[0]] # Attach VPN to single subnet. Reduce cost
  endpoint_vpc_id            = module.vpc.vpc_id
  tls_subject_common_name    = "int.example.com"
  saml_provider_arn          = aws_iam_saml_provider.vpn.arn

  authorization_rules = {}

  additional_routes = {
    "${module.vpc.intra_subnets[0]}" = "172.16.0.0/24"
  }

  authorization_rules_all_groups = {
    full_access_private_subnet_0 = module.vpc.private_subnets_cidr_blocks[0]
  }

  tags = var.tags
}
#################################################################################################################################### Gateway

# resource "aws_api_gateway_rest_api" "example" {
#   body = jsonencode({
#     openapi = "3.0.1"
#     info = {
#       title   = "example"
#       version = "1.0"
#     }
#     paths = {
#       "/home" = {
#         get = {
#           x-amazon-apigateway-integration = {
#             httpMethod           = "GET"
#             payloadFormatVersion = "1.0"
#             type                 = "HTTP_PROXY"
#             uri                  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
#           }
#         }
#       }
#     }
#   })

#   name = "example"
# }

# resource "aws_api_gateway_deployment" "example" {
#   rest_api_id = aws_api_gateway_rest_api.example.id

#   triggers = {
#     redeployment = sha1(jsonencode(aws_api_gateway_rest_api.example.body))
#   }

#   lifecycle {
#     create_before_destroy = true
#   }
# }

# resource "aws_api_gateway_stage" "example" {
#   deployment_id = aws_api_gateway_deployment.example.id
#   rest_api_id   = aws_api_gateway_rest_api.example.id
#   stage_name    = "example"
# }
module "api_gateway" {
  source = "terraform-aws-modules/apigateway-v2/aws"

  name          = "dev-http"
  description   = "My awesome HTTP API Gateway"
  protocol_type = "HTTP"

  cors_configuration = {
    allow_headers = ["content-type", "x-amz-date", "authorization", "x-api-key", "x-amz-security-token", "x-amz-user-agent"]
    allow_methods = ["*"]
    allow_origins = ["*"]
  }

  # Custom domain
  domain_name                 = "terraform-aws-modules.modules.tf"
  domain_name_certificate_arn = "arn:aws:acm:eu-west-1:052235179155:certificate/2b3a7ed9-05e1-4f9e-952b-27744ba06da6"

  # Access logs
  default_stage_access_log_destination_arn = "arn:aws:logs:eu-west-1:835367859851:log-group:debug-apigateway"
  default_stage_access_log_format          = "$context.identity.sourceIp - - [$context.requestTime] \"$context.httpMethod $context.routeKey $context.protocol\" $context.status $context.responseLength $context.requestId $context.integrationErrorMessage"

  # Routes and integrations
  integrations = {
    "POST /" = {
      lambda_arn             = "arn:aws:lambda:eu-west-1:052235179155:function:my-function"
      payload_format_version = "2.0"
      timeout_milliseconds   = 12000
    }

    "GET /some-route-with-authorizer" = {
      integration_type = "HTTP_PROXY"
      integration_uri  = "some url"
      authorizer_key   = "azure"
    }

    "$default" = {
      lambda_arn = "arn:aws:lambda:eu-west-1:052235179155:function:my-default-function"
    }
  }

  authorizers = {
    "azure" = {
      authorizer_type  = "JWT"
      identity_sources = "$request.header.Authorization"
      name             = "azure-auth"
      audience         = ["d6a38afd-45d6-4874-d1aa-3c5c558aqcc2"]
      issuer           = "https://sts.windows.net/aaee026e-8f37-410e-8869-72d9154873e4/"
    }
  }

  tags = {
    Name = "http-apigateway"
  }
}
#################################################################################################################################### WAF
resource "aws_wafv2_web_acl" "example" {
  name  = "web-acl-association-example"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "friendly-metric-name"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "example" {
  resource_arn = aws_api_gateway_stage.example.arn
  web_acl_arn  = aws_wafv2_web_acl.example.arn
}
#################################################################################################################################### Route53
module "route53" {
  source  = "terraform-aws-modules/route53/aws"
  version = "2.9.0"
}
module "zones" {
  source  = "terraform-aws-modules/route53/aws//modules/zones"
  version = "~> 2.0"

  zones = {
    "terraform-aws-modules-example.com" = {
      comment = "terraform-aws-modules-examples.com (production)"
      tags = {
        env = "production"
      }
    }

    "myapp.com" = {
      comment = "myapp.com"
    }
  }

  tags = {
    ManagedBy = "Terraform"
  }
}

module "records" {
  source  = "terraform-aws-modules/route53/aws//modules/records"
  version = "~> 2.0"

  zone_name = keys(module.zones.route53_zone_zone_id)[0]

  records = [
    {
      name    = "apigateway1"
      type    = "A"
      alias   = {
        name    = "d-10qxlbvagl.execute-api.eu-west-1.amazonaws.com"
        zone_id = "ZLY8HYME6SFAD"
      }
    },
    {
      name    = ""
      type    = "A"
      ttl     = 3600
      records = [
        "10.10.10.10",
      ]
    },
  ]

  depends_on = [module.zones]
}
############################################################################################################################### DocumentDB (with MongoDB compatibility)
esource "aws_docdb_subnet_group" "service" {
  name       = "tf-${var.name}"
  subnet_ids = ["${module.vpc.private_subnets}"]
}

resource "aws_docdb_cluster_instance" "service" {
  count              = 1
  identifier         = "tf-${var.name}-${count.index}"
  cluster_identifier = "${aws_docdb_cluster.service.id}"
  instance_class     = "${var.docdb_instance_class}"
}

resource "aws_docdb_cluster" "service" {
  skip_final_snapshot     = true
  db_subnet_group_name    = "${aws_docdb_subnet_group.service.name}"
  cluster_identifier      = "tf-${var.name}"
  engine                  = "docdb"
  master_username         = "tf_${replace(var.name, "-", "_")}_admin"
  master_password         = "${var.docdb_password}"
  db_cluster_parameter_group_name = "${aws_docdb_cluster_parameter_group.service.name}"
  vpc_security_group_ids = ["${aws_security_group.service.id}"]
}

resource "aws_docdb_cluster_parameter_group" "service" {
  family = "docdb3.6"
  name = "tf-${var.name}"

  parameter {
    name  = "tls"
    value = "disabled"
  }
}
