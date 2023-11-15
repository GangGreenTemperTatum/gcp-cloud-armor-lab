module "application" {
  source = "../../modules/application"

  environment                = var.environment
  region                     = var.region
  default_zones              = var.default_zones
  project_id                 = var.project_id
  recapatcha_allowed_domains = var.recapatcha_allowed_domains
}
