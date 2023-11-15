module "myapp" {
  source = "../../../../modules/myapp"

  environment                = var.environment
  project_id                 = var.project_id
  region                     = var.region
  default_zones              = var.default_zones
  recapatcha_allowed_domains = var.recapatcha_allowed_domains

  disabled_submodules = [
    "monitoring",
    "migration",
  ]
}