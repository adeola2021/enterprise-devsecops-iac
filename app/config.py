import os


API_KEY = os.getenv("ENTERPRISE_API_KEY")

DATABASE_PASSWORD = os.getenv("ENTERPRISE_DATABASE_PASSWORD")


if not API_KEY:
    raise RuntimeError("ENTERPRISE_API_KEY is not configured.")

if not DATABASE_PASSWORD:
    raise RuntimeError("ENTERPRISE_DATABASE_PASSWORD is not configured.")
