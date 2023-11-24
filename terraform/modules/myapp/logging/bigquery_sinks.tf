/*
  BIG QUERY LOGGING SINKS
*/

locals {
  sinks = {

    production : {
      cloudarmorwaf : {
        dataset : "cloudarmorwaf_prod"
        filter : "resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(block-with-modsec-crs)"
      }
    } # EO production

    staging : {
      cloudarmorwaf : {
        dataset : "cloudarmorwaf_prod"
        filter : "resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(block-with-modsec-crs)"
      }
    } # EO staging

    development :
      cloudarmorwaf : {
        dataset : "cloudarmorwaf_dev"
        filter : "resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(block-with-modsec-crs)"
      }
  } # EO development

  destination_prefix = "bigquery.googleapis.com/projects/XXXYYY/datasets"

}

resource "google_logging_project_sink" "bigquery_sinks" {
  for_each = local.sinks[var.environment]

  name        = each.key
  destination = "${local.destination_prefix}/${each.value.dataset}"
  filter      = each.value.filter

  unique_writer_identity = true
  bigquery_options {
    use_partitioned_tables = true
  }
}

/*
  ACCESS GRANTS FOR PER-SINK SERVICE ACCOUNTS
*/

data "google_project" "XXXYYY" {
  project_id = "XXXYYY"
}

resource "google_bigquery_dataset_iam_member" "editor" {
  for_each = google_logging_project_sink.bigquery_sinks

  role       = "roles/bigquery.dataEditor"
  project    = data.google_project.XXXYYY.project_id
  member     = each.value.writer_identity
  dataset_id = local.sinks[var.environment][each.key].dataset
}
