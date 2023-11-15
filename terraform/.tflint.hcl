plugin "aws" {
    enabled = true
    version = "0.27.0"
    source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

plugin "google" {
  enabled    = true
  source     = "github.com/terraform-linters/tflint-ruleset-google"
  version    = "0.26.0"
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = false
}

rule "terraform_documented_variables" {
  enabled = false
}

rule "terraform_module_pinned_source" {
  enabled = true
  style   = "semver"
}

rule "terraform_module_version" {
  enabled = true
  exact   = true
}

rule "terraform_naming_convention" {
  enabled = true
}

rule "terraform_unused_required_providers" {
  enabled = false
}

rule "terraform_standard_module_structure" {
  enabled = false
}
