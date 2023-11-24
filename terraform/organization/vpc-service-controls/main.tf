module "bq_access_level_members" {
  source      = "terraform-google-modules/vpc-service-controls/google//modules/access_level"
  version     = "4.0.1"
  description = "BigQuery Access Level"
  policy      = module.access_context_manager_policy.policy_id
  name        = var.bq_access_level_name
  members     = var.bq_prod_members
  regions     = var.regions
}
