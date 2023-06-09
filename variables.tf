variable "region" {
  default = "us-west1"
}

variable "region_zone" {
  default = "us-west1-a"
}

variable "project_name" {
  description = "The ID of the Google Cloud project"
  default     = "gcp-cloud-armor-waf-lab"
  sensitive   = true
}

variable "credentials_file_path" {
  description = "Path to the JSON file used to describe your account credentials"
  default     = "./gcp-cloud-armor-waf-lab-78fe4d97f8b5.json"
}

variable "ip_white_list" {
  description = "A list of ip addresses that can be white listed through security policies"
  type        = list(string)
  default     = ["23.16.163.89/32"]
}
variable "log_level" {
  type        = string
  description = "Log Level"
  default     = "VERBOSE" #Options are VERBOSE or NORMAL
  # https://cloud.google.com/armor/docs/request-logging#verbose-logging
}

variable "json_parsing" {
  type        = string
  description = "JSON Parsing support"
  default     = "DISABLED" #Options are DISABLED or STANDARD
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
      src_ip_ranges  = ["23.16.163.89/32"]
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
variable "default_rules_2" {
  default = {
    def_rule = {
      action         = "deny(403)"
      priority       = "2147483647"
      versioned_expr = "SRC_IPS_V1"
      src_ip_ranges  = ["*"]
      description    = "Default Explicit Deny"
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

# --------------------------------- 
# Throttling traffic rules
# --------------------------------- 
variable "throttle_rules_endpoints" {
  default = {
    def_rule = {
      action                            = "throttle"
      priority                          = "4000"
      expression                        = <<-EOT
        request.method.matches('POST') && request.path.contains('RegisterWithEmail') || request.path.contains('InviteUser') || request.path.contains('RequestPasswordReset')
      EOT
      description                       = "Prevent rate limit abuse"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "IP"
      rate_limit_threshold_count        = "50"
      rate_limit_threshold_interval_sec = "10"
      #ban_http_request_count            = 10000
      #ban_http_request_interval_sec     = 600
      #ban_duration_sec                  = 120
      preview = true
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
    preview                           = bool
    })
  )
}
variable "throttle_rules_auth" {
  default = {
    def_rule = {
      action                            = "throttle"
      priority                          = "4001"
      expression                        = "request.path.contains('auth')"
      description                       = "Prevent Brute Force and Creds Stuffing Attacks"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "ALL" #https://cloud.google.com/armor/docs/rate-limiting-overview#identifying_clients_for_rate_limiting
      rate_limit_threshold_count        = "10"
      rate_limit_threshold_interval_sec = "10"
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
    preview                           = bool
    })
  )
}
variable "throttle_rules" {
  default = {
    def_rule = {
      action                            = "throttle"
      priority                          = "4002"
      versioned_expr                    = "SRC_IPS_V1"
      src_ip_ranges                     = ["103.235.111.255/32"]
      description                       = "Throttling traffic generic rule placeholder random IP from Wallis and Futuna"
      conform_action                    = "allow"
      exceed_action                     = "deny(429)"
      enforce_on_key                    = "ALL" #https://cloud.google.com/armor/docs/rate-limiting-overview#identifying_clients_for_rate_limiting
      rate_limit_threshold_count        = "100"
      rate_limit_threshold_interval_sec = "60"
      preview                           = false
    }
  }
  type = map(object({
    action                            = string
    priority                          = string
    versioned_expr                    = string
    src_ip_ranges                     = list(string)
    description                       = string
    conform_action                    = string
    exceed_action                     = string
    enforce_on_key                    = string
    rate_limit_threshold_count        = number
    rate_limit_threshold_interval_sec = number
    preview                           = bool
    })
  )
}

# --------------------------------- 
# Bot Detection & Captcha rules
# --------------------------------- 
variable "bot_captcha_rules" {
  default = {
    def_rule = {
      action      = "deny(404)"
      priority    = "4002"
      expression  = "(token.recaptcha_session.valid) && (token.recaptcha_action.valid)"
      description = "Deny Bots from ReCaptcha Session Tokens"
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
      priority    = "4003"
      expression  = "request.path.contains('admin') || request.path.contains('robots') || request.path.contains('wp-admin') || request.path.contains('wordpress') || request.path.contains('.wp') || request.path.contains('.php') || request.path.endsWith('.wp')"
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

# --------------------------------- 
# Countries limitation rules
# --------------------------------- 
variable "countries_rules" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "3000"
      expression  = "'[CN, RU]'.contains(origin.region_code)"
      description = "Deny if region code is listed"
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
# Banned Countries - I.E OFAC & Global Affairs
# Country Codes - https://wits.worldbank.org/wits/wits/witshelp/content/codes/country_codes.htm
# ---------------------------------
variable "banned_countries" {
  default = {
    def_rule = {
      action      = "deny(502)"
      priority    = "100"
      expression  = <<-EOT
        '[RU, SY, BY, KP, CN, IR]'.contains(origin.region_code)
      EOT
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
# OWASP top 10 rules
# --------------------------------- 
variable "owasp_rules" {
  default = {
    #https://cloud.google.com/armor/docs/rule-tuning#sql_injection_sqli
    rule_sqli = {
      action      = "deny(403)"
      priority    = "1000"
      description = "SQL injection"
      preview     = true

      ### Detect Level 1
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942110-sqli','owasp-crs-v030001-id942120-sqli','owasp-crs-v030001-id942150-sqli','owasp-crs-v030001-id942180-sqli','owasp-crs-v030001-id942200-sqli','owasp-crs-v030001-id942210-sqli','owasp-crs-v030001-id942260-sqli','owasp-crs-v030001-id942300-sqli','owasp-crs-v030001-id942310-sqli','owasp-crs-v030001-id942330-sqli','owasp-crs-v030001-id942340-sqli','owasp-crs-v030001-id942380-sqli','owasp-crs-v030001-id942390-sqli','owasp-crs-v030001-id942400-sqli','owasp-crs-v030001-id942410-sqli','owasp-crs-v030001-id942430-sqli','owasp-crs-v030001-id942440-sqli','owasp-crs-v030001-id942450-sqli','owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942251-sqli','owasp-crs-v030001-id942420-sqli','owasp-crs-v030001-id942431-sqli','owasp-crs-v030001-id942460-sqli','owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2 & 3
      #expression  = "evaluatePreconfiguredExpr('sqli-stable',['owasp-crs-v030001-id942421-sqli','owasp-crs-v030001-id942432-sqli'])"

      ### Detect Level 1,2,3 & 4
      expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#cross-site_scripting_xss
rule_xss = {
      action                  = "deny(404)"
      priority                = "1001"
      description             = "Cross-site scripting"
      preview                 = true
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 1
      exclude_target_rule_ids = [""]

      ### Include all signatures at paranoia level 1
      #expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"

      ### Detect Level 1
      #expression = "evaluatePreconfiguredExpr('xss-stable',['owasp-crs-v030001-id941150-xss','owasp-crs-v030001-id941320-xss','owasp-crs-v030001-id941330-xss','owasp-crs-v030001-id941340-xss'])"

      ### Detect Level 1 & 2
      #expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#local_file_inclusion_lfi
    rule_lfi = {
      action      = "deny(403)"
      priority    = "1002"
      description = "Local file inclusion"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#remote_code_execution_rce
    rule_rce = {
      action      = "deny(403)"
      priority    = "1003"
      description = "Remote code execution"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#remote_file_inclusion_rfi
    rule_rfi = {
      action      = "deny(403)"
      priority    = "1004"
      description = "Remote file inclusion"
      preview     = true

      ### Detect Level 1
      #expression  = "evaluatePreconfiguredExpr('rfi-stable', ['owasp-crs-v030001-id931130-rfi'])"

      ### Detect Level 1 & 2
      expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#method_enforcement
    rule_methodenforcement = {
      action      = "deny(403)"
      priority    = "1005"
      description = "Method enforcement"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('methodenforcement-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#scanner_detection
    rule_scandetection = {
      action      = "deny(403)"
      priority    = "1006"
      description = "Scanner detection"
      preview     = true

      ### Detect Level 1
      #expression  = "evaluatePreconfiguredExpr('scannerdetection-stable',['owasp-crs-v030001-id913101-scannerdetection','owasp-crs-v030001-id913102-scannerdetection'])"

      ### Detect Level 1 & 2
      expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#protocol_attack
    rule_protocolattack = {
      action      = "deny(403)"
      priority    = "1007"
      description = "Protocol Attack"
      preview     = true

      ### Detect Level 1
      #expression  = "evaluatePreconfiguredExpr('protocolattack-stable',['owasp-crs-v030001-id921151-protocolattack','owasp-crs-v030001-id921170-protocolattack'])"                  

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('protocolattack-stable',['owasp-crs-v030001-id921170-protocolattack'])"

      ### Detect Level 1,2 & 3
      expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#php
    rule_php = {
      action      = "deny(403)"
      priority    = "1008"
      description = "PHP Injection Attack"
      preview     = true

      ### Detect Level 1
      #expression  = "evaluatePreconfiguredExpr('php-stable',['owasp-crs-v030001-id933151-php','owasp-crs-v030001-id933131-php','owasp-crs-v030001-id933161-php','owasp-crs-v030001-id933111-php'])"

      ### Detect Level 1 & 2
      #expression  = "evaluatePreconfiguredExpr('php-stable',['owasp-crs-v030001-id933131-php','owasp-crs-v030001-id933161-php','owasp-crs-v030001-id933111-php'])"

      ### Detect Level 1,2 & 3
      expression = "evaluatePreconfiguredExpr('php-v33-stable')"
    }
    #https://cloud.google.com/armor/docs/rule-tuning#session_fixation
    rule_sessionfixation = {
      action      = "deny(403)"
      priority    = "1009"
      description = "Session Fixation Attack"
      preview     = true

      ### Detect Level 1
      expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
    }
    rule_java = {
      action      = "deny(403)"
      priority    = "1010"
      description = "Java Attack"
      preview     = true

      ### Detect Level 1, 2 and 3
      expression = "evaluatePreconfiguredExpr('java-v33-stable')"
    }
    rule_nodejs = {
      action      = "deny(403)"
      priority    = "1011"
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


# --------------------------------- 
# Custom GCP-Driven CVE & Log4j rules
# --------------------------------- 
variable "apache_log4j_rule" {
  default = {
    # https://cloud.google.com/armor/docs/rule-tuning#cves_and_other_vulnerabilities
    rule_apache_log4j = {
      action      = "deny(403)"
      priority    = "2000"
      description = "Apache Log4j CVE-2021-44228 and CVE-2021-45046"
      preview     = true

      ### Detect Level 1 Basic rule
      #expression      = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id144228-cve','owasp-crs-v030001-id244228-cve','owasp-crs-v030001-id344228-cve'])"

      ### Detect Level 1 only
      #expression      = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id244228-cve','owasp-crs-v030001-id344228-cve'])"

      ### Detect Level 1 & 3, decrease sensitivity
      #expression      = "evaluatePreconfiguredExpr('cve-canary',['owasp-crs-v030001-id244228-cve'])"

      ### Detect Level 1 & 3 - very sensitive
      expression = "evaluatePreconfiguredExpr('cve-canary')"
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

variable "json-sqli-canary_rule" {
  default = {
    # https://cloud.google.com/armor/docs/rule-tuning#cves_and_other_vulnerabilities
    rule_apache_log4j = {
      action      = "deny(403)"
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
