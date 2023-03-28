# Example for using Cloud Armor https://cloud.google.com/armor/
#

resource "random_id" "instance_id" {
  byte_length = 4
}

# Configure the Google Cloud provider
provider "google" {
  credentials = file(var.credentials_file_path)
  project     = var.project_name
  region      = var.region
  zone        = var.region_zone
}

# Set up a backend to be proxied to:
# A single instance in a pool running nginx with port 80 open will allow end to end network testing
resource "google_compute_instance" "cluster1" {
  name         = "armor-gce-${random_id.instance_id.hex}"
  machine_type = "f1-micro"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Ephemeral IP
    }
  }

  metadata_startup_script = "sudo apt-get update; sudo apt-get install -yq nginx; sudo service nginx restart"
}

resource "google_compute_firewall" "cluster1" {
  name     = "armor-firewall"
  network  = "default"
  priority = 1000

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  source_ranges = var.ip_white_list
}

resource "google_compute_firewall" "explicitdeny" {
  name     = "explicit-deny"
  network  = "default"
  priority = 1001

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}
resource "google_compute_instance_group" "webservers" {
  name        = "instance-group-all"
  description = "An instance group for the single GCE instance"

  instances = [
    google_compute_instance.cluster1.self_link,
  ]

  named_port {
    name = "http"
    port = "80"
  }
}

resource "google_compute_target_pool" "example" {
  name = "armor-pool"

  instances = [
    google_compute_instance.cluster1.self_link,
  ]

  health_checks = [
    google_compute_http_health_check.health.name,
  ]
}

resource "google_compute_http_health_check" "health" {
  name               = "armor-healthcheck"
  request_path       = "/"
  check_interval_sec = 1
  timeout_sec        = 1
}

resource "google_compute_backend_service" "website" {
  name        = "armor-backend"
  description = "Our company website"
  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 10
  enable_cdn  = false

  backend {
    group = google_compute_instance_group.webservers.self_link
  }

  security_policy = google_compute_security_policy.security-policy-1.self_link

  health_checks = [google_compute_http_health_check.health.self_link]
}

# -------------------------------------------------------------------------------------
# WAF Mod SECURITY RULES
# -------------------------------------------------------------------------------------

# Cloud Armor Security policies
resource "google_compute_security_policy" "security-policy-1" {
  name        = "armor-security-policy"
  description = "NGINX GCP Cloud Armor Policy"
  project     = var.project_name

  advanced_options_config {
    log_level    = var.log_level
    json_parsing = var.json_parsing
  }
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
  # Reject all traffic that hasn't been whitelisted.
  rule {
    action   = "deny(404)"
    priority = "2147483647"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "Default rule, higher priority overrides it"
  }


  # --------------------------------- 
  # Default rules
  # --------------------------------- 
  dynamic "rule" {
    for_each = var.default_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        versioned_expr = rule.value.versioned_expr
        config {
          src_ip_ranges = rule.value.src_ip_ranges
        }
      }
    }
  }

  # --------------------------------- 
  # Throttling traffic rules
  # --------------------------------- 
  dynamic "rule" {
    for_each = var.throttle_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        versioned_expr = rule.value.versioned_expr
        config {
          src_ip_ranges = rule.value.src_ip_ranges
        }
      }
      rate_limit_options {
        conform_action = rule.value.conform_action
        exceed_action  = rule.value.exceed_action
        enforce_on_key = rule.value.enforce_on_key
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
      }
    }
  }

  # --------------------------------- 
  # Country limitation
  # --------------------------------- 
  dynamic "rule" {
    for_each = var.countries_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        expr {
          expression = rule.value.expression
        }
      }
    }
  }

  # --------------------------------- 
  # OWASP top 10 rules
  # --------------------------------- 
  dynamic "rule" {
    for_each = var.owasp_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        expr {
          expression = rule.value.expression
        }
      }
    }
  }

  # --------------------------------- 
  # Custom Log4j rule
  # --------------------------------- 
  dynamic "rule" {
    for_each = var.apache_log4j_rule
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        expr {
          expression = rule.value.expression
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.json-sqli-canary_rule
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      match {
        expr {
          expression = rule.value.expression
        }
      }
    }
  }
} # End of Dynamic Rule Block
# -------------------------------------------------------------------------------------
# EOF WAF Mod SECURITY RULES
# -------------------------------------------------------------------------------------

# Front end of the load balancer
resource "google_compute_global_forwarding_rule" "default" {
  name       = "armor-rule"
  target     = google_compute_target_http_proxy.default.self_link
  port_range = "80"
}

resource "google_compute_target_http_proxy" "default" {
  name    = "armor-proxy"
  url_map = google_compute_url_map.default.self_link
}

resource "google_compute_url_map" "default" {
  name            = "armor-url-map"
  default_service = google_compute_backend_service.website.self_link

  host_rule {
    hosts        = ["mysite.com"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.website.self_link

    path_rule {
      paths   = ["/*"]
      service = google_compute_backend_service.website.self_link
    }
  }
}

# A variable for extracting the external IP address of the VM
output "Frontend-LB-for-NGINX-ip" {
  value = google_compute_global_forwarding_rule.default.ip_address
}

#output "cURL-connectivity" {
#  value = startswith("curl https://", ["google_compute_global_forwarding_rule.default.ip_address"])
#}