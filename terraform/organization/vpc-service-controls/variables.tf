variable "parent_id" {
  description = "The parent of this AccessPolicy in the Cloud Resource Hierarchy. As of now, only organization are accepted as parent."
  type        = string
  default     = "XXXYYY"
}

variable "policy_name" {
  description = "The policy's name."
  type        = string
  default     = "my_context_access_policy"
}

variable "bigquery_XXXYYY_protected_project_ids" {
  description = "Project id and number of the project INSIDE the regular service perimeter. This map variable expects an \"id\" for the project id and \"number\" key for the project number."
  type        = object({ id = string, number = number })
  default     = { id = "<XXXYYY>", number = XXXYYY }
}

variable "projects_allowed_to_access_bigquery" {
  description = "A list of projects allowed to accesss BigQuery in production"
  type        = list(string)
  default     = ["projects/XXXYYY"]
}

# The following SA's will require adding:
# The SA used for CI/CD to merge the changes to GCP
# The SA's auto-created per-log-router sink via terraform/modules/myapp/logging/bigquery_sinks.tf (I.E 3 x additional SA's per SA)

variable "looker_service_account" {
  description = "GCP Service Account that Looker uses to access BigQuery"
  type        = string
  default     = [
    "serviceAccount:XXXYYY.iam.gserviceaccount.com",#CI/CD Terraform SA
    "serviceAccount:XXXYYY.iam.gserviceaccount.com",#prod log router SA
    "serviceAccount:XXXYYY.iam.gserviceaccount.com",#dev log router SA
    "serviceAccount:XXXYYY.iam.gserviceaccount.com"#stg log router SA
  ]
}

variable "looker_project" {
  description = "GCP Project that Looker uses to access BigQuery"
  type        = string
  default     = "projects/XXXYYY"
}

# https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/blob/9840bf76ccaad9b910561a11cf9d68b480aeb40a/terraform/modules/myapp/logging/bigquery_sinks.tf#L33-L44
# The terraform/modules/myapp/logging/bigquery_sinks.tf creates a SA per-log-sink but requires adding to the vpc-service-controls.tf for BigQuery access once the SA has been provisioned

variable "bq_prod_members" {
  description = "An allowed list of members (users, service accounts). The signed-in identity originating the request must be a part of one of the provided members. If not specified, a request may come from any user (logged in/not logged in, etc.). Formats: user:{emailid}, serviceAccount:{emailid}"
  type        = list(string)
  default = [
    "serviceAccount:<TBC>",
  ]
}

variable "regions" {
  description = "The request must originate from one of the provided countries/regions. Format: A valid ISO 3166-1 alpha-2 code."
  type        = list(string)
  default     = []
}

variable "bq_access_level_name" {
  description = "Access level name of the Access Policy."
  type        = string
  default     = "bigquey_access_level"
}
