# -----------------------------------------------------------------------------
# SECURITY
# ------------------------------------------------------------------------------

module "security" {
  depends_on = [module.project]
  source     = "./security"

  project_id  = var.project_id
  environment = var.environment
  region      = var.region
  recapatcha_allowed_domains = var.recapatcha_allowed_domains
}
