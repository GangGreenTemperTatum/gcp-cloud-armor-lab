This is a very "_scrap note_" approach to troubleshooting false positives from CRS rules applied to GCP CloudArmor Security Policies

## **Resources**:

- [GCS Docs](https://cloud.google.com/armor/docs/troubleshooting)
- [See project repo docs](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/blob/main/README.md)

## **GCP Logs**:

- It is recommended to enable [`--verbose` Logging](https://cloud.google.com/armor/docs/request-logging) for troubleshooting
- - Verify configuration with the following `gcloud` SDK command:

```
scripts % gcloud compute security-policies describe <security-policy-name> | grep 'advancedOptionsConfig' -A 5
advancedOptionsConfig:
  jsonCustomConfig: {}
  jsonParsing: STANDARD
  logLevel: VERBOSE <--- 
creationTimestamp: '2022-11-23T12:48:30.768-08:00'
description: Block with OWASP rules.
```

- The following query may assist with investigations when the rule in question is **actively blocking** (I.E `preview = false` mode is configured):
- - Remove `jsonPayload.enforcedSecurityPolicy.outcome="DENY"` to perform log analysis when the rule in question is **not actively blocking** (I.E `preview = true` mode is configured)
 
```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>) -- <--- Where <security-policy-name> is your Security Policy name in question
jsonPayload.enforcedSecurityPolicy.priority="1001" -- <--- The rule ID in question
timestamp>="2023-05-31T08:00:00Z" AND timestamp<="2023-06-14T00:02:00Z" -- <--- Time the rule was applied until now or later date
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
```

## **Example False Positive**:

- The `json` output emitted below in this example:

```
    "insertId": "XXXXXXXXX",
    "jsonPayload": {
      "@type": "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
      "previewSecurityPolicy": { <----- Ignore the `previewSecurityPolicy` nested json in this instance which is related to what rule would be matched if enabled in rule table hierarchy
        "matchedLength": 13,
        "matchedFieldLength": 1800,
        "name": "<security-policy-name>",
        "matchedOffset": 8,
        "configuredAction": "ALLOW",
        "matchedFieldType": "ARG_NAMES",
        "priority": 1000,
        "matchedFieldValue": "\": \"Related C",
        "outcome": "ACCEPT",
        "preconfiguredExprIds": [
          "owasp-crs-v030301-id942260-sqli"
        ]
      },
      "remoteIp": "xxx.xxx.xxx.xxx",
      "cacheDecision": [
        "RESPONSE_HAS_CONTENT_TYPE",
        "REQUEST_HAS_AUTHORIZATION",
        "CACHE_MODE_USE_ORIGIN_HEADERS"
      ],
      "enforcedSecurityPolicy": {
        "outcome": "DENY",
        "matchedFieldLength": 1800,
        "preconfiguredExprIds": [
          "owasp-crs-v030301-id941380-xss" <----- Here is the rule in question applying the active block
        ],
        "matchedOffset": 532,
        "configuredAction": "DENY", <----- Here is the rule in question applying the active block
        "matchedFieldType": "ARG_NAMES",
        "matchedLength": 6,
        "name": "block-with-modsec-crs",
        "matchedFieldValue": "{{id}}", <----- Here what triggered the above rule
        "priority": 1001
      },
      "statusDetails": "body_denied_by_security_policy"
    },
```

- Run a [search](https://github.com/search?q=repo%3Acoreruleset%2Fcoreruleset%20941&type=code) within the [CRS repo](https://github.com/search?q=repo%3Acoreruleset%2Fcoreruleset%20941&type=code) for the Rule ID in question

![image](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/assets/104169244/72f5e103-474f-43ed-b64a-d96c3f87c64b)

- Takes us to the [code in question](https://github.com/coreruleset/coreruleset/blob/483630449e176cbd4e22571511acefaab5e5a870/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf#L17)

![image](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/assets/104169244/2c4617b2-ec04-47f3-81d7-b3d82c3cd976)

- In this example, is `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:941011,phase:1,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"`

<br> 

💾 EOF
