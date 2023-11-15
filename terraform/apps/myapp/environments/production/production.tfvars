environment = "production"
project_id  = "my-production-environment"
region      = "us-central1"
default_zones = [
  "us-central1-a",
  "us-central1-b",
  "us-central1-c",
  "us-central1-f"
]

recapatcha_allowed_domains = [
  "localhost",
  "x.my-api-environment.com",
  "api.my-api-environment.com"
  "api.x.my-api-environment.com"
]
