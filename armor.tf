# -------------------------------------------------------------------------------------
# WAF Mod SECURITY RULES
# -------------------------------------------------------------------------------------

resource "google_compute_security_policy" "policy" {
  name        = "block-with-modsec-crs"
  description = "Block with OWASP rules."
  project     = var.project_id

  advanced_options_config {
    log_level    = var.log_level
    json_parsing = var.json_parsing
  }

  # Reject all traffic that hasn't been whitelisted.
  rule {
    action   = "allow"
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

  dynamic "adaptive_protection_config" {
    for_each = var.layer_7_ddos_defense_enable == true ? ["adaptive_protection_config"] : []
    content {
      layer_7_ddos_defense_config {
        enable          = var.layer_7_ddos_defense_enable
        rule_visibility = var.layer_7_ddos_defense_rule_visibility
      }
    }
  }

  # ------------------------deny(404)---------
  # Spam Abuse
  # ---------------------------------

  # Leaving commented out for easy quick implementation if required at a later stage by replacing srcip(s)

  /*
  dynamic "rule" {
    for_each = var.banned_ips
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
*/

  # ---------------------------------
  # Vendor Whitelisting Rules
  # ---------------------------------



  # ---------------------------------
  # Banned Countries - I.E OFAC & Global Affairs
  # ---------------------------------

  dynamic "rule" {
    for_each = var.banned_countries
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
  # Scanners, Crawlers and Malicious Recon/OSINT
  # ---------------------------------
  dynamic "rule" {
    for_each = var.crawler_osint_rules
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
    for_each = var.gpt_crawler_rules
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
  # Bot Detection & Captcha rules
  # ---------------------------------

  dynamic "rule" {
    for_each = var.ec2_bot_blocking_register
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
    for_each = var.ec2_bot_blocking_register_contd
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
    for_each = var.ec2_bot_blocking_apikey
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
    for_each = var.ec2_bot_blocking_apikey_contd
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
    for_each = var.malicious_actor_signup
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
    for_each = var.malicious_actor_signup_contd
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
    for_each = var.malicious_key_creation
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
    for_each = var.malicious_key_creation_contd
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
    for_each = var.bot_captcha_action_token_allow
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview
      #actionname  = rule.value.recaptcha_action_name
      match {
        expr {
          expression = rule.value.expression
        }
      }
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.bot_captcha_action_token_deny
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

  /*
  dynamic "rule" {
    for_each = var.bot_captcha_action_token_challenge
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
    for_each = var.bot_captcha_session_token
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
*/

  /*
  dynamic "rule" {
    for_each = var.ec2_bot_monitoring
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
*/

  # ---------------------------------
  # Throttling traffic rules
  # ---------------------------------

  # https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_security_policy

  dynamic "rule" {
    for_each = var.throttle_rules_auth_creds_attacks
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
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.throttle_rules_ban_endpoints_post
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
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.throttle_rules_ban_endpoints_options
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
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.throttle_rules_ban_api_key_abuse
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
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  dynamic "rule" {
    for_each = var.throttle_rules_ban_endpoints_orgabuse
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
      rate_limit_options {
        conform_action   = rule.value.conform_action
        exceed_action    = rule.value.exceed_action
        enforce_on_key   = rule.value.enforce_on_key
        ban_duration_sec = rule.value.ban_duration_sec
        rate_limit_threshold {
          count        = rule.value.rate_limit_threshold_count
          interval_sec = rule.value.rate_limit_threshold_interval_sec
        }
        ban_threshold {
          count        = rule.value.ban_threshold_count
          interval_sec = rule.value.ban_threshold_interval_sec
        }
      }
    }
  }

  # ---------------------------------
  # OWASP CRS Rules
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

  # ---------------------------------------------------
  # Custom OWASP CRS Modsec Hacks - RISK-816 - Ads
  # Defined outside of the Dynamic rule block, for when OWASP CRS defaults are too sensitive, regardless of paranoia levels
  # ---------------------------------------------------

  dynamic "rule" {
    for_each = var.xss_based_script_requesturls
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
  # Manual HTTP Method Enforcements
  # ---------------------------------
  # NFR submitted with GCP who do not support enforcing HTTP Version
  # `evaluatePreconfiguredExpr('methodenforcement-v33-stable')` OWASP CRS rule is too prone to many false positives and risky, even with Paranoia Level 1

  dynamic "rule" {
    for_each = var.http_method_protect_rule
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
    for_each = var.http_method_protect_rule_ext
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
    for_each = var.http_method_protect_rule_block
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
  # Custom gRPC rule
  # ---------------------------------
  dynamic "rule" {
    for_each = var.app_grpc_rule
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
    for_each = var.json_sqli_canary_rule
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
