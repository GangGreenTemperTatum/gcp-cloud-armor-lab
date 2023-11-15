environment = "staging"
project_id  = "my-staging-environment"
region      = "us-central1"
default_zones = [
  "us-central1-a",
  "us-central1-b",
  "us-central1-c",
  "us-central1-f"
]

recapatcha_allowed_domains = [
  "localhost",
  "stg.x.my-development-environment.com",
  "staging.api.my-development-environment.com"
  "staging.api.x.my-development-environment.com"
]
