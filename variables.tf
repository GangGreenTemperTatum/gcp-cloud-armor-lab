variable "region" {
  default = "us-west1"
}

variable "region_zone" {
  default = "us-west1-a"
}

variable "project_name" {
  description = "The ID of the Google Cloud project"
  default     = "gcp-cloud-armor-waf-lab"
  sensitive   = true
}

variable "credentials_file_path" {
  description = "Path to the JSON file used to describe your account credentials"
  default     = "./gcp-cloud-armor-waf-lab-78fe4d97f8b5.json"
}

variable "ip_white_list" {
  description = "A list of ip addresses that can be white listed through security policies"
  type        = list(string)
  default     = ["23.16.163.89/32"]
}