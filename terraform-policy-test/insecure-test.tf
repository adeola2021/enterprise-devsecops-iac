resource "aws_security_group" "policy_test_insecure" {

  name = "policy-test-insecure-sg"

  ingress {

    description = "SSH from anywhere"

    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  tags = {
    Environment = "development"
  }
}
