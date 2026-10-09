from pytm import (
    TM,
    Actor,
    Server,
    Datastore,
    Boundary,
    Dataflow,
    Classification
)

tm = TM("Enterprise DevSecOps Threat Model")
tm.description = """
Threat model for an enterprise microservices application consisting
of an API Gateway, Authentication Service, Order Service, databases,
and an external payment service.
"""

# ============================================================
# TRUST BOUNDARIES
# ============================================================

internet = Boundary("Internet Zone")
application = Boundary("Enterprise Application Zone")
data_zone = Boundary("Protected Data Zone")
external = Boundary("External Third-Party Zone")

# ============================================================
# ACTOR
# ============================================================

user = Actor("Internet User")
user.inBoundary = internet

# ============================================================
# APPLICATION COMPONENTS
# ============================================================

api_gateway = Server("API Gateway")
api_gateway.inBoundary = application
api_gateway.OS = "Linux"
api_gateway.usesTLS = True

auth_service = Server("Authentication Service")
auth_service.inBoundary = application
auth_service.OS = "Linux"
auth_service.usesTLS = True

order_service = Server("Order Service")
order_service.inBoundary = application
order_service.OS = "Linux"
order_service.usesTLS = True

# ============================================================
# DATASTORES
# ============================================================

user_db = Datastore("User Database")
user_db.inBoundary = data_zone
user_db.isEncrypted = True

order_db = Datastore("Order Database")
order_db.inBoundary = data_zone
order_db.isEncrypted = True

# ============================================================
# EXTERNAL SERVICE
# ============================================================

payment_api = Server("External Payment API")
payment_api.inBoundary = external
payment_api.usesTLS = True

# ============================================================
# DATA FLOWS
# ============================================================

df1 = Dataflow(user, api_gateway, "HTTPS Request")
df1.protocol = "HTTPS"
df1.dstPort = 443
df1.usesTLS = True

df2 = Dataflow(api_gateway, auth_service, "Authentication Request")
df2.protocol = "HTTPS"
df2.dstPort = 443
df2.usesTLS = True

df3 = Dataflow(api_gateway, order_service, "Order Request")
df3.protocol = "HTTPS"
df3.dstPort = 443
df3.usesTLS = True

df4 = Dataflow(auth_service, user_db, "User Lookup")
df4.protocol = "TLS"
df4.usesTLS = True

df5 = Dataflow(order_service, order_db, "Order Data")
df5.protocol = "TLS"
df5.usesTLS = True

df6 = Dataflow(order_service, payment_api, "Payment Transaction")
df6.protocol = "HTTPS"
df6.dstPort = 443
df6.usesTLS = True


# ============================================================
# PHASE 4: DEVSECOPS TRUST BOUNDARIES
# ============================================================

developer_zone = Boundary("Developer Workstation Zone")
github_zone = Boundary("GitHub Source Control Zone")
ci_zone = Boundary("GitHub Actions CI Zone")
identity_zone = Boundary("Federated Identity Zone")
aws_zone = Boundary("AWS Infrastructure Zone")

# ============================================================
# PHASE 4: ACTORS AND COMPONENTS
# ============================================================

developer = Actor("DevSecOps Developer")
developer.inBoundary = developer_zone

github_repo = Datastore("GitHub Source Repository")
github_repo.inBoundary = github_zone

github_runner = Server("GitHub Actions Runner")
github_runner.inBoundary = ci_zone
github_runner.OS = "Linux"
github_runner.description = (
    "Ephemeral CI runner executing pull-request security checks."
)

pytm_engine = Server("PyTM Threat Modeling Engine")
pytm_engine.inBoundary = ci_zone

semgrep_engine = Server("Semgrep SAST Engine")
semgrep_engine.inBoundary = ci_zone

checkov_engine = Server("Checkov IaC Scanner")
checkov_engine.inBoundary = ci_zone

opa_engine = Server("OPA Conftest Policy Engine")
opa_engine.inBoundary = ci_zone

terraform_engine = Server("Terraform Plan Engine")
terraform_engine.inBoundary = ci_zone

github_oidc = Server("GitHub OIDC Token Issuer")
github_oidc.inBoundary = identity_zone

aws_sts = Server("AWS STS")
aws_sts.inBoundary = identity_zone
aws_sts.onAWS = True

iam_role = Server("AWS Terraform Automation IAM Role")
iam_role.inBoundary = aws_zone
iam_role.onAWS = True

aws_resources = Datastore("AWS Managed Infrastructure")
aws_resources.inBoundary = aws_zone

terraform_state = Datastore("Terraform Remote State")
terraform_state.inBoundary = aws_zone
terraform_state.isEncrypted = True

github_security = Datastore("GitHub Security Findings")
github_security.inBoundary = github_zone

# ============================================================
# PHASE 4: DEVSECOPS DATA FLOWS
# ============================================================

def secure_flow(source, destination, name):
    flow = Dataflow(source, destination, name)
    flow.protocol = "HTTPS"
    flow.dstPort = 443
    return flow

secure_flow(
    developer, github_repo,
    "Git Push and Pull Request"
)

secure_flow(
    github_repo, github_runner,
    "Pull Request Workflow Trigger"
)

secure_flow(
    github_runner, pytm_engine,
    "Threat Model Execution"
)

secure_flow(
    github_runner, semgrep_engine,
    "Source Code SAST Scan"
)

secure_flow(
    github_runner, checkov_engine,
    "Terraform Static Security Scan"
)

secure_flow(
    github_runner, terraform_engine,
    "Terraform Plan Generation"
)

secure_flow(
    terraform_engine, opa_engine,
    "Terraform Plan JSON Policy Evaluation"
)

secure_flow(
    github_runner, github_oidc,
    "OIDC Token Request"
)

secure_flow(
    github_runner, aws_sts,
    "Assume Role With Web Identity"
)

secure_flow(
    aws_sts, iam_role,
    "Federated Role Authorization"
)

secure_flow(
    terraform_engine, aws_resources,
    "AWS Infrastructure Operations"
)

secure_flow(
    terraform_engine, terraform_state,
    "Terraform State Access"
)

secure_flow(
    semgrep_engine, github_security,
    "Semgrep SARIF Findings"
)

secure_flow(
    checkov_engine, github_security,
    "Checkov SARIF Findings"
)

# ============================================================
# PROCESS THREAT MODEL
# ============================================================

if __name__ == "__main__":
    tm.process()
