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
# PROCESS THREAT MODEL
# ============================================================

if __name__ == "__main__":
    tm.process()
