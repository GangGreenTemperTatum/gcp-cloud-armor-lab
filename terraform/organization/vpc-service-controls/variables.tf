# https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/blob/9840bf76ccaad9b910561a11cf9d68b480aeb40a/terraform/modules/myapp/logging/bigquery_sinks.tf#L33-L44
# The terraform/modules/myapp/logging/bigquery_sinks.tf creates a SA per-log-sink but requires adding to the vpc-service-controls.tf for BigQuery access once the SA has been provisioned

variable "bq_prod_members" {
  description = "An allowed list of members (users, service accounts). The signed-in identity originating the request must be a part of one of the provided members. If not specified, a request may come from any user (logged in/not logged in, etc.). Formats: user:{emailid}, serviceAccount:{emailid}"
  type        = list(string)
  default = [
    "serviceAccount:<TBC>",
  ]
}
