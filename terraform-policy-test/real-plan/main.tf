terraform {
  required_version = ">= 1.5.0"
}

resource "terraform_data" "policy_test" {
  input = {
    Environment = "dev"
    Owner       = "DevSecOps"
    Project     = "Enterprise-DevSecOps"
    CostCenter  = "IT-SEC-001"
  }
}
