# ------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ------------------------------------------------------------------------------

variable "environment" {
  description = "The environment this module will run in"
  type        = string
}

variable "project_id" {
  description = "The project this module will run in"
  type        = string
}

variable "region" {
  description = "The region this module will run in"
  type        = string
}

# ------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ------------------------------------------------------------------------------

variable "log_level" {
  type        = string
  description = "Log Level"
  default     = "VERBOSE" #Options are VERBOSE or NORMAL
  # https://cloud.google.com/armor/docs/request-logging#verbose-logging
}

variable "json_parsing" {
  type        = string
  description = "JSON Parsing support"
  default     = "STANDARD" #Options are DISABLED or STANDARD
}

# ---------------------------------
# Default rules
# ---------------------------------
variable "default_rules" {
  default = {
    def_rule = {
      action         = "allow"
      priority       = "2147483646"
      versioned_expr = "SRC_IPS_V1"
      src_ip_ranges  = ["0.0.0.0/0"]
      description    = "Whitelist /32 IPv4 host addresses"
      preview        = false
    }
  }
  type = map(object({
    action         = string
    priority       = string
    versioned_expr = string
    src_ip_ranges  = list(string)
    description    = string
    preview        = bool
    })
  )
}

# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_security_policy

# ---------------------------------
# Spam Abuse - Ads
# ---------------------------------

# Leaving commented out for easy quick implementation if required at a later stage by replacing srcip(s)

/*
variable "banned_ips" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "50"
      expression  = "inIpRange(origin.ip, '3.83.122.183/32') || inIpRange(origin.ip, '44.192.107.198/32') || inIpRange(origin.ip, '34.204.42.192/32')"
      description = "Explicit Blocklist Bad IPs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}
*/

# ---------------------------------
# Vendor Whitelisting Rules
# ---------------------------------



# ---------------------------------
# Banned Countries - I.E OFAC & Global Affairs
# Follow ISO 3166-1 alpha 2 expressions here - https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
# ---------------------------------

variable "banned_countries" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "100"
      expression  = "'[RU, SY, BY, KP, CN, IR, CU]'.contains(origin.region_code)"
      description = "Block prohibited countries as per ISO 3166-1 alpha 2 region codes"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# ---------------------------------
# Scanners, Crawlers and Malicious Recon/OSINT
# ---------------------------------
variable "crawler_osint_rules" {
  default = {
    def_rule = {
      action      = "deny(404)"
      priority    = "200"
      expression  = "request.path.contains('admin') || request.path.contains('robots') || request.path.contains('wordpress') || request.path.contains('.wp') || request.path.contains('.php')"
      description = "Stop malicious crawling/OSINT activity"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "gpt_crawler_rules" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "201"
      expression  = "(has(request.headers['user-agent']) && request.headers['user-agent'].contains('GPTBot')) || (has(request.headers['User-Agent']) && request.headers['User-Agent'].matches('(?i:gptbot)'))"
      description = "Detect GPTBot crawling and activity"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# ---------------------------------
# Throttling traffic rules
# ---------------------------------

# Replace with reCaptcha + Throttling/Banning (397) following log analysis and confidence to deploy non-preview

variable "throttle_rules_ban_endpoints_orgabuse" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "398"
      expression                        = <<-EOT
        request.method.matches('POST') && request.path.contains('Signup')
      EOT
      description                       = "Ban rate limit abuse against Organization creation (Strict)"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "2"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 3600 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 2
      ban_threshold_interval_sec        = 60
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

variable "throttle_rules_auth_creds_attacks" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "399"
      expression                        = <<-EOT
        request.method.matches('POST') && request.path.endsWith('API/Auth')
      EOT
      description                       = "Rate limit logins for credential stuffing and password sprays"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "5"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 300 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 10
      ban_threshold_interval_sec        = 60
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

variable "throttle_rules_ban_endpoints_post" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "401"
      expression                        = <<-EOT
        request.method.matches('POST') && (request.path.contains('InviteUser') || request.path.contains('RequestPasswordReset'))
      EOT
      description                       = "Ban rate limit abuse"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "5"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 300 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 10
      ban_threshold_interval_sec        = 60
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

# Seperate rule required required as cannot filter on POST and OPTIONS in same rule (`1:1: Matches subexpressions count of 2 exceeded maximum of 1 per expression.`)

variable "throttle_rules_ban_endpoints_options" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "402"
      expression                        = <<-EOT
        request.method.matches('OPTIONS') && (request.path.contains('InviteUser') || request.path.contains('RequestPasswordReset'))
      EOT
      description                       = "Ban rate limit abuse"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "5"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 300 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 10
      ban_threshold_interval_sec        = 60
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

variable "throttle_rules_ban_api_key_abuse" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "403"
      expression                        = <<-EOT
        request.method.matches('POST') && request.path.endsWith('API/CreateAPIKey')
      EOT
      description                       = "Ban rate limit abuse against API key creation"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "2"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 300 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 3
      ban_threshold_interval_sec        = 60
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

# ---------------------------------
# Bot Detection & Captcha rules
# ---------------------------------

# Suspicious ASN's:
# https://cleantalk.org/blacklists/asn
# Blocked countries should be enforced via explicit geo-region blocking above

variable "ec2_bot_blocking_register" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "442"
      expression  = "request.method.matches('POST') && request.path.contains('Signup') && (origin.asn == 16509 || origin.asn == 14618 || origin.asn == 396982)"
      description = "Deny Account Creation - Bots or Malicious Scripts from EC2 GCP, AWS, Digital Ocean ASNs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "ec2_bot_blocking_register_contd" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "443"
      expression  = "request.method.matches('POST') && request.path.contains('Signup') && (origin.asn == 14061)"
      description = "Deny Account Creation - Bots or Malicious Scripts from EC2 GCP, AWS, Digital Ocean ASNs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "ec2_bot_blocking_apikey" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "444"
      expression  = "request.method.matches('POST') && request.path.endsWith('API/CreateAPIKey') && (origin.asn == 16509 || origin.asn == 14618 || origin.asn == 396982)"
      description = "Deny API Key Creation - Bots or Malicious Scripts from EC2 GCP, AWS, Digital Ocean ASNs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "ec2_bot_blocking_apikey_contd" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "445"
      expression  = "request.method.matches('POST') && request.path.endsWith('API/CreateAPIKey') && (origin.asn == 14061)"
      description = "Deny API Key Creation - Bots or Malicious Scripts from EC2 GCP, AWS, Digital Ocean ASNs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "malicious_actor_signup" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "446"
      expression  = "request.method.matches('POST') && request.path.contains('Signup') && (origin.asn == 36352 || origin.asn == 8075 || origin.asn == 20473)"
      description = "Deny high spam rate ASN's for countries and regions implicitly permitted"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "malicious_actor_signup_contd" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "447"
      expression  = "request.method.matches('POST') && request.path.contains('Signup') && (origin.asn == 9009)"
      description = "Deny high spam rate ASN's for countries and regions implicitly permitted"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "malicious_key_creation" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "448"
      expression  = "request.method.matches('POST') && request.path.contains('CreateAPIKey') && (origin.asn == 36352 || origin.asn == 8075 || origin.asn == 20473)"
      description = "Deny high spam rate ASN's for countries and regions implicitly permitted"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "malicious_key_creation_contd" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "449"
      expression  = "request.method.matches('POST') && request.path.contains('CreateAPIKey') && (origin.asn == 9009)"
      description = "Deny high spam rate ASN's for countries and regions implicitly permitted"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

### Ads TICKET-908 ###

# ReCaptcha Enterprise with WAF integration limitation - https://stackoverflow.com/questions/76229084/cloud-armor-recaptcha-with-domain-validation

# Since terraform doesn't look to support the `--recaptcha-action-site-keys` function/flag, you need to add '--recaptcha-action-site-keys "example-site-key-1"' via gcloud
# https://cloud.google.com/sdk/docs/release-notes - For both 396 and 397 rule IDs

# The `recaptcha_action_name` is currently supported, I just need to work out how to embed that in `armor.tf` - https://registry.terraform.io/modules/GoogleCloudPlatform/cloud-armor/google/latest?tab=inputs

/*
Ads gcloud bug raised here - https://cloud.google.com/support/docs/issue-trackers
# https://issuetracker.google.com/u/1/issues/300157692
crapi % gcloud beta compute security-policies rules update 396 --security-policy block-with-modsec-crs --description="test" --recaptcha-action-site-keys="x_account_registration_waf"
ERROR: gcloud crashed (AttributeError): 'NoneType' object has no attribute 'exprOptions'
*/

variable "bot_captcha_action_token_allow" {
  default = {
    def_rule = {
      action                            = "rate_based_ban"
      priority                          = "396"
      expression                        = <<-EOT
        request.path.endsWith('Signup') && token.recaptcha_action.score >= 0.8 && (token.recaptcha_action.valid)
      EOT
      description                       = "Allow reCAPTCHA Enterprise action-token with a score no less than 0.8 to account creations and requires explicit Action Name"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "2"
      rate_limit_threshold_interval_sec = "10"
      ban_duration_sec                  = 3600 # Terraform docs are incorrect and this is mandatory
      ban_threshold_count               = 2
      ban_threshold_interval_sec        = 60
      #recaptcha_action_name             = "register"
      preview                           = true
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    expression                        = string
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    ban_duration_sec                  = number
    ban_threshold_count               = number
    ban_threshold_interval_sec        = number
    preview                           = bool
    })
  )
}

# Replaced with improved 396

/*
variable "bot_captcha_action_token_allow" {
  default = {
    def_rule = {
      action                = "allow"
      priority              = "397"
      expression            = "request.path.endsWith('Signup') && token.recaptcha_action.score >= 0.8 && (token.recaptcha_action.valid)"
      description           = "Allow reCAPTCHA Enterprise action-token with a score no less than 0.8 to account creations and requires explicit Action Name"
      recaptcha_action_name = "register"
      preview               = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}
*/

variable "bot_captcha_action_token_deny" {
  default = {
    def_rule = {
      action      = "deny(403)"
      priority    = "397"
      expression  = "request.path.endsWith('Signup') && token.recaptcha_action.score < 0.8 && (token.recaptcha_action.valid)"
      description = "Explicit Deny reCAPTCHA Enterprise action-token with a score no less than 0.8 to account creations as well as incorrect Action Name"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# Not creating Challenge-based (friction) ReCaptcha Enterprise keys, or ReCaptcha Enterprise keys based on Session Tokens at this time

/*
variable "bot_captcha_action_token_challenge" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "450"
      expression  = "request.path.endsWith('Signup') && token.recaptcha_action.score == 0.5 && (token.recaptcha_action.valid)"
      description = "Challenge reCAPTCHA Enterprise action-token with a score no less than 0.8 to account creations"
      preview     = true
      recaptcha_action_name = "register"
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}
*/

/*
variable "bot_captcha_session_token" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "459"
      expression  = "request.path.endsWith('Signup') && token.recaptcha_session.score >= 0.8 && (token.recaptcha_action.valid)"
      description = "PLACEHOLDER - Deny reCAPTCHA Enterprise session-token with a score no less than 0.8 to account creations"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}
*/

# Enterprise token lives here - https://console.cloud.google.com/security/recaptcha?project=xxxx-xxxx-xxxx (redacted)

/*
variable "ec2_bot_monitoring" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "451"
      expression  = "(origin.asn==16509 || origin.asn==15169 || origin.asn== 14061)"
      description = "Monitor Bots or Malicious Scripts from EC2 GCP, DigitalOcean and AWS ASNs"
      preview     = true
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}
*/

# ---------------------------------
# OWASP CRS Rules
# ---------------------------------
variable "owasp_rules" {
  default = {
    #https://cloud.google.com/armor/docs/rule-tuning#sql_injection_sqli
    rule_sqli_p1 = {
      action      = "deny(404)"
      priority    = "1001"
      description = "iSQL paranoia level 1"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942110-sqli','owasp-crs-v030001-id942120-sqli','owasp-crs-v030001-id942150-sqli','owasp-crs-v030001-id942180-sqli','owasp-crs-v030001-id942200-sqli','owasp-crs-v030001-id942210-sqli','owasp-crs-v030001-id942260-sqli','owasp-crs-v030001-id942300-sqli','owasp-crs-v030001-id942310-sqli','owasp-crs-v030001-id942330-sqli','owasp-crs-v030001-id942340-sqli','owasp-crs-v030001-id942380-sqli','owasp-crs-v030001-id942390-sqli','owasp-crs-v030001-id942400-sqli','owasp-crs-v030001-id942410-sqli','owasp-crs-v030001-id942430-sqli','owasp-crs-v030001-id942440-sqli','owasp-crs-v030001-id942450-sqli','owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2 & 3
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2,3 & 4
      #expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    rule_sqli_p2 = {
      action      = "deny(404)"
      priority    = "1002"
      description = "iSQL paranoia level 1 2"
      preview     = true

      ### Detect Level 1
      #expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942110-sqli','owasp-crs-v030001-id942120-sqli','owasp-crs-v030001-id942150-sqli','owasp-crs-v030001-id942180-sqli','owasp-crs-v030001-id942200-sqli','owasp-crs-v030001-id942210-sqli','owasp-crs-v030001-id942260-sqli','owasp-crs-v030001-id942300-sqli','owasp-crs-v030001-id942310-sqli','owasp-crs-v030001-id942330-sqli','owasp-crs-v030001-id942340-sqli','owasp-crs-v030001-id942380-sqli','owasp-crs-v030001-id942390-sqli','owasp-crs-v030001-id942400-sqli','owasp-crs-v030001-id942410-sqli','owasp-crs-v030001-id942430-sqli','owasp-crs-v030001-id942440-sqli','owasp-crs-v030001-id942450-sqli','owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1 & 2
      expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2 & 3
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2,3 & 4
      #expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    rule_sqli_p2_auth = {
      action      = "deny(404)"
      priority    = "1003"
      description = "iSQL paranoia level 2 against `auth` endpoint"
      preview     = false

      ### Detect Level 1
      #expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942110-sqli','owasp-crs-v030001-id942120-sqli','owasp-crs-v030001-id942150-sqli','owasp-crs-v030001-id942180-sqli','owasp-crs-v030001-id942200-sqli','owasp-crs-v030001-id942210-sqli','owasp-crs-v030001-id942260-sqli','owasp-crs-v030001-id942300-sqli','owasp-crs-v030001-id942310-sqli','owasp-crs-v030001-id942330-sqli','owasp-crs-v030001-id942340-sqli','owasp-crs-v030001-id942380-sqli','owasp-crs-v030001-id942390-sqli','owasp-crs-v030001-id942400-sqli','owasp-crs-v030001-id942410-sqli','owasp-crs-v030001-id942430-sqli','owasp-crs-v030001-id942440-sqli','owasp-crs-v030001-id942450-sqli','owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1 & 2
      expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli']) && request.path.endsWith('API/Auth')"

      ### Detect Level 1,2 & 3
      #expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli']) && request.path.endsWith('API/Auth')"

      ### Detect Level 1,2,3 & 4
      #expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    rule_sqli_p3_auth = {
      action      = "deny(404)"
      priority    = "1004"
      description = "iSQL paranoia level 3 against `auth` endpoint"
      preview     = false

      ### Detect Level 1
      #expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942110-sqli','owasp-crs-v030001-id942120-sqli','owasp-crs-v030001-id942150-sqli','owasp-crs-v030001-id942180-sqli','owasp-crs-v030001-id942200-sqli','owasp-crs-v030001-id942210-sqli','owasp-crs-v030001-id942260-sqli','owasp-crs-v030001-id942300-sqli','owasp-crs-v030001-id942310-sqli','owasp-crs-v030001-id942330-sqli','owasp-crs-v030001-id942340-sqli','owasp-crs-v030001-id942380-sqli','owasp-crs-v030001-id942390-sqli','owasp-crs-v030001-id942400-sqli','owasp-crs-v030001-id942410-sqli','owasp-crs-v030001-id942430-sqli','owasp-crs-v030001-id942440-sqli','owasp-crs-v030001-id942450-sqli','owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2 & 3
      expression = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli']) && request.path.endsWith('API/Auth')"

      ### Detect Level 1,2,3 & 4
      #expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#cross-site_scripting_xss

    rule_xss_paranoia_one = {
      action      = "deny(404)"
      priority    = "1010"
      description = "Cross-site scripting paranoia level 1"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('xss-stable',['owasp-crs-v030001-id941150-xss','owasp-crs-v030001-id941320-xss','owasp-crs-v030001-id941330-xss','owasp-crs-v030001-id941340-xss'])"

      ### Detect Level 1 & 2
      #expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
    }

    rule_xss_paranoia_two = {
      action      = "deny(404)"
      priority    = "1011"
      description = "Cross-site scripting paranoia level 2"
      preview     = true

      ### Detect Level 1
      #expression = "evaluatePreconfiguredExpr('xss-stable',['owasp-crs-v030001-id941150-xss','owasp-crs-v030001-id941320-xss','owasp-crs-v030001-id941330-xss','owasp-crs-v030001-id941340-xss'])"

      ### Detect Level 1 & 2
      expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#local_file_inclusion_lfi
    rule_lfi = {
      action      = "deny(404)"
      priority    = "1020"
      description = "Local file inclusion"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#remote_code_execution_rce
    rule_rce = {
      action      = "deny(404)"
      priority    = "1030"
      description = "Remote code execution"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#remote_file_inclusion_rfi
    rule_rfi = {
      action      = "deny(404)"
      priority    = "1040"
      description = "Remote file inclusion"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('rfi-stable', ['owasp-crs-v030001-id931130-rfi'])"

      ### Detect Level 1 & 2
      #expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#method_enforcement
    rule_methodenforcement = {
      action      = "deny(404)"
      priority    = "1050"
      description = "Method enforcement"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('methodenforcement-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#scanner_detection
    rule_scandetection = {
      action      = "deny(404)"
      priority    = "1060"
      description = "Scanner detection"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('scannerdetection-stable',['owasp-crs-v030001-id913101-scannerdetection','owasp-crs-v030001-id913102-scannerdetection'])"

      ### Detect Level 1 & 2
      #expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#protocol_attack
    rule_protocolattack = {
      action      = "deny(404)"
      priority    = "1070"
      description = "Protocol Attack"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('protocolattack-stable',['owasp-crs-v030001-id921151-protocolattack','owasp-crs-v030001-id921170-protocolattack'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('protocolattack-stable',['owasp-crs-v030001-id921170-protocolattack'])"

      ### Detect Level 1,2 & 3
      #expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#php
    rule_php = {
      action      = "deny(404)"
      priority    = "1080"
      description = "PHP Injection Attack"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('php-stable',['owasp-crs-v030001-id933151-php','owasp-crs-v030001-id933131-php','owasp-crs-v030001-id933161-php','owasp-crs-v030001-id933111-php'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('php-stable',['owasp-crs-v030001-id933131-php','owasp-crs-v030001-id933161-php','owasp-crs-v030001-id933111-php'])"

      ### Detect Level 1,2 & 3
      #expression = "evaluatePreconfiguredExpr('php-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#session_fixation
    rule_sessionfixation = {
      action      = "deny(404)"
      priority    = "1090"
      description = "Session Fixation Attack"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
    }
    rule_java = {
      action      = "allow"
      priority    = "1100"
      description = "Java Attack"
      preview     = true

      ### Detect Level 1, 2 and 3
      expression = "evaluatePreconfiguredExpr('java-v33-stable')"
    }
    rule_nodejs = {
      action      = "allow"
      priority    = "1111"
      description = "NodeJS Attack"
      preview     = true

      ### Detect Level 1, 2 and 3
      expression = "evaluatePreconfiguredExpr('nodejs-v33-stable')"
    }
  } # End of `rule` definition
  type = map(object({
    action      = string
    priority    = string
    description = string
    preview     = bool
    expression  = string
    })
  )
}

# ------------------------------------------------------------------------------
# Custom OWASP CRS Modsec Hacks - TICKET-816 - Ads
# Defined outside of the Dynamic rule block, for when OWASP CRS defaults are too sensitive, regardless of paranoia levels
# ------------------------------------------------------------------------------

variable "xss_based_script_requesturls" {
  default = {
    def_rule = {
      action      = "deny(404)"
      priority    = "1009"
      expression  = "request.path.matches('(?i:script)') || request.path.contains('script')"
      description = "Malicious XSS <script> tags in RequestURLs"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# ---------------------------------
# Manual HTTP Method Enforcements
# ---------------------------------
# NFR submitted with GCP who do not support enforcing HTTP Version
# `evaluatePreconfiguredExpr('methodenforcement-v33-stable')` OWASP CRS rule is too prone to many false positives and TICKETy, even with Paranoia Level 1

variable "http_method_protect_rule" {
  default = {
    def_rule = {
      action      = "allow"
      priority    = "1047"
      expression  = "request.method=='GET' || request.method=='HEAD' || request.method=='POST' || request.method=='PUT' || request.method=='DELETE'"
      description = "Protect HTTP Methods"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "http_method_protect_rule_ext" {
  default = {
    def_rule = {
      action      = "allow"
      priority    = "1048"
      expression  = "request.method=='CONNECT' || request.method=='OPTIONS' || request.method=='TRACE' || request.method=='PATCH'"
      description = "Protect HTTP Methods"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

variable "http_method_protect_rule_block" {
  default = {
    def_rule = {
      action      = "deny(404)"
      priority    = "1049"
      expression  = "request.method.matches('.*')"
      description = "Block non-conforming HTTP Methods"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# ---------------------------------
# Custom gRPC rule
# ---------------------------------

variable "app_grpc_rule" {
  default = {
    def_rule = {
      action      = "deny(404)"
      priority    = "1900"
      expression  = "request.method.contains('PROP')"
      description = "Stop Malicious gRPC Requests"
      preview     = false
    }
  }
  type = map(object({
    action      = string
    priority    = string
    expression  = string
    description = string
    preview     = bool
    })
  )
}

# ---------------------------------
# Custom GCP-Driven CVE & Log4j rules
# ---------------------------------
variable "apache_log4j_rule" {
  default = {
    # https://cloud.google.com/armor/docs/rule-tuning#cves_and_other_vulnerabilities
    rule_apache_log4j = {
      action      = "deny(404)"
      priority    = "2000"
      description = "Apache Log4j CVE-2021-44228 and CVE-2021-45046"
      preview     = true

      ### Detect Level 1 Basic rule
      #expression      = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id144228-cve','owasp-crs-v030001-id244228-cve','owasp-crs-v030001-id344228-cve'])"

      ### Detect Level 1 only
      #expression      = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id244228-cve','owasp-crs-v030001-id344228-cve'])"

      ### Detect Level 1 & 3, decrease sensitivity
      expression = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id244228-cve'])"

      ### Detect Level 1 & 3 - very sensitive
      #expression = "evaluatePreconfiguredExpr('cve-canary')"
    }
  }
  type = map(object({
    action      = string
    priority    = string
    description = string
    preview     = bool
    expression  = string
    })
  )
}

variable "json_sqli_canary_rule" {
  default = {
    # https://cloud.google.com/armor/docs/rule-tuning#cves_and_other_vulnerabilities
    rule_apache_log4j = {
      action      = "deny(404)"
      priority    = "2001"
      description = "JSON-based SQL injection bypass vulnerability 942550-sqli"
      preview     = true

      ### Detect Level 2
      expression = "evaluatePreconfiguredExpr('json-sqli-canary')"
    }
  }
  type = map(object({
    action      = string
    priority    = string
    description = string
    preview     = bool
    expression  = string
    })
  )
}
