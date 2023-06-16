# GCP Cloud Armor WAF Security Policy Lab and Deploying via Terraform

* Author: @[GangGreenTemperTatum](https://github.com/GangGreenTemperTatum)

* This is my personal created GCP lab for testing and learning about Cloud Armor WAF Security Policies
* GCP lab environment is deployed and ongoing maintained via Terraform IaC provisioning tools

## Resources:
- [OWASP CRS](https://owasp.org/www-project-modsecurity-core-rule-set/)
- [OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset)
- [`terraform - google_compute_security_policy`](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_security_policy)
- [ISO 3166-1 alpha-2 (for blocking regions](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
- [Cloud Armor Terraform Module](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor)
- [Configure Google Cloud Armor security policies](https://cloud.google.com/armor/docs/configure-security-policies)
- [Configure custom rules language attributes](https://cloud.google.com/armor/docs/rules-language-reference)
- [Rate limiting overview](https://cloud.google.com/armor/docs/rate-limiting-overview)

![image](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/assets/104169244/c3f2643a-9f13-4237-8c50-22c43d95d0ce)

You can refer to the following image created by [Priyanka Vergadia](https://blog.searce.com/cloud-armor-securing-google-infrastructure-against-web-attacks-8fb335174978) (credit)

![image](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/assets/104169244/c8b6ee0e-d4cf-4c4d-be40-9d5718fa5f67)

## Recommended WAF Testing Frameworks

1. [Wallarm](https://github.com/wallarm/gotestwaf)
2. [SignalSci](https://github.com/signalsciences/waf-testing-framework)
3. [Fastly](https://github.com/fastly/ftw)
4. [F5](https://github.com/f5devcentral/f5-waf-tester)

