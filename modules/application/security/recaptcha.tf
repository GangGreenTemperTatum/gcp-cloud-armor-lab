# Use count to enumerate projects and do not create a ReCaptcha key resource in beta as it already exists

resource "google_recaptcha_enterprise_key" "recaptcha_enterprise_scoring_key" {
  count        = var.environment != "beta" ? 1 : 0
  display_name = "signup_abuse_account_registration_waf"
  project      = var.project_id

  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = false
    allow_amp_traffic = false
    allowed_domains   = var.recapatcha_allowed_domains # All subdomains of an allowed domain are automatically allowed
  }

  labels = {
    label-one = var.project_id,
    label-two = "waf_enforced"
  }
}
