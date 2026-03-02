// Terraform stubs for SecretSentinel infrastructure.
//
// This file intentionally contains only high-level placeholders for:
// - ECS Fargate services (CLI-adjacent services, detection engine, API gateway).
// - RDS PostgreSQL 16 for persistent storage.
// - SQS queues for rotation events.
//
// Full infrastructure definitions will be added once the core
// developer protection layer (CLI + detection engine) is stable.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type        = string
  description = "AWS region for SecretSentinel infrastructure."
  default     = "us-east-1"
}

// module "network" {
//   source = "./modules/network"
// }
//
// module "ecs" {
//   source = "./modules/ecs"
// }
//
// module "rds" {
//   source = "./modules/rds"
// }
//
// module "sqs" {
//   source = "./modules/sqs"
// }
