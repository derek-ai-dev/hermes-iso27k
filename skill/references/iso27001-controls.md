# ISO 27001:2022 Annex A Controls — Agent Mapping

Agent-relevant controls and how Hermes logs map to them.

## A.5 — Information security policies
- **A.5.1**: Topics for information security — `on_config_change`
- **A.5.2**: Information security roles and responsibilities — session ownership events

## A.6 — Organization of information security
- **A.6.1**: Information security roles and responsibilities — audit owner tagging
- **A.6.2**: Segregation of duties — twoapprover flags on sensitive plugin installs
- **A.6.3**: Contact with authorities — security incident records in evidence bundle
- **A.6.4**: Information security in project management — change/cron audit entries

## A.7 — Human resource security
- **A.7.1**: Prior to employment — access provisioning events
- **A.7.2**: During employment — access-restriction rule hits
- **A.7.3**: Termination or change of employment — automated access review flags
- **A.7.4**: Responsibilities after termination — cleanup reminders via cron skill

## A.8 — Access control
- **A.8.1**: User access provisioning — terminal/file/web access log
- **A.8.2**: User access rights review — approval outcomes tagged in hash chain
- **A.8.3**: Information access restriction — file-read/write path coverage
- **A.8.4**: Access control to source code — write_file / terminal edits to source paths
- **A.8.5**: Secure authentication — `.env`/secrets/config edits
- **A.8.6**: Capacity management — session and tool-use rate evidence
- **A.8.7**: Protection against malware — plugin install approvals
- **A.8.8**: Management of technical vulnerabilities — plugin/skill update logs
- **A.8.9**: Configuration management — `on_config_change` + config snapshot in evidence
- **A.8.10**: Information deletion — `rm` deletion patterns in terminal logs
- **A.8.11**: Data masking — redaction completeness audits
- **A.8.12**: Data leakage prevention — exfiltration pattern detection rules
- **A.8.13**: Information backup — backup/cron evidence bundle
- **A.8.14**: Redundancy of information processing facilities — container profile changes
- **A.8.15**: Logging — plugin audit log + `/iso27k verify`
- **A.8.16**: Monitoring activities — cron-driven control reports
- **A.8.17**: Clock synchronization — host time variance notes in evidence bundle
- **A.8.18**: Use of privileged utility programs — sudo/elevated command tags
- **A.8.19**: Use of cryptography — secret-access rule hits
- **A.8.20**: Information security in development environments — env-specific path tags
- **A.8.21**: Security testing — `/iso27k verify` + defensive scan logs
- **A.8.22**: Outsourced development — third-party plugin origin in metadata
- **A.8.23**: System and services acquisition — MCP server additions
- **A.8.24**: Cryptography and key management — key material access events
- **A.8.25**: Secure development life cycle — skill mutation policy hits
- **A.8.26**: Secure coding — code write events with control tags

## A.9 — Cryptography
- **A.9.1**: Cryptographic controls — key creation/rotation events
- **A.9.2**: Key management — vault/secrets access audit events
- **A.9.3**: Use of cryptography — encrypted transport rule hits
- **A.9.4**: Cryptography usage — secret file read/write/delete approvals

## A.10 — Physical and environmental security
- **A.10.1**: Secure areas — out of direct agent scope
- **A.10.2**: Equipment — local device inventory evidence bundle

## A.11 — Communications security
- **A.11.1**: Network controls — approved endpoint lists
- **A.11.2**: Information transfer — web_request/terminal transfer events
- **A.11.3**: Electronic messaging — platform messaging tool events

## A.12 — Operations security
- **A.12.1**: Documented operating procedures — `on_config_change`, `cron schedule`
- **A.12.2**: Change management — skill/plugin mutation events
- **A.12.3**: Capacity management — cron-driven scan/modify frequency evidence
- **A.12.4**: Separation of development, test, and production — session profiles
- **A.12.5**: Controls against malware — plugin install approvals
- **A.12.6**: Management of technical vulnerabilities — skill updates
- **A.12.7**: Information security incident management — incident readiness flag
- **A.12.8**: Management of information security incidents — breach alerting rules
- **A.12.9**: Management of information security evidence — hash-chain reports

## A.13 — Supplier relationships
- **A.13.1**: Information security in supplier relationships — MCP server metadata
- **A.13.2**: Supplier service delivery management — MCP heartbeat evidence
- **A.13.3**: Information and communication technology supply chain — plugin origin
- **A.13.4**: Supplier security incident reporting — shared incident records

## A.14 — System acquisition, development, and maintenance
- **A.14.1**: Information security requirements — skill install provenance
- **A.14.2**: Secure development — skill mutations, code write events
- **A.14.3**: Test data protection — synthetic data tags
- **A.14.4**: System development security — imports and plugin boundaries
- **A.14.5**: System development security — config snapshot in evidence bundle
- **A.14.6**: Security in development environments — .env/config redaction checks
- **A.14.7**: Secure coding policy — language/syntax gating rules
- **A.14.8**: Testing — `/iso27k verify` output in evidence
- **A.14.9**: System acceptance — release gating via cron skill
- **A.14.10**: Outsourced development — external dependency integrity
- **A.14.11**: Environmental security — container profile tags
- **A.14.12**: Supplier service requirements — MCP server contract metadata
- **A.14.13**: Information system resilience — restart/recovery evidence
- **A.14.14**: Framework acquisition — skill/plugin provenance chain

## A.15 — Supplier relationships security
- **A.15.1**: Supplier relationship security policy — contract terms summary
- **A.15.2**: Supplier service delivery management — SLA monitoring events
- **A.15.3**: ICT supply chain — third-party plugin registry metadata

## A.16 — Information security incident management
- **A.16.1**: Management of information security incidents — policy violation alerts
- **A.16.2**: Assessment and decision on information security events — rule hits
- **A.16.3**: Response to information security incidents — incident bundle contents
- **A.16.4**: Assessment and decision on information security events — post-incident summary

## A.17 — Information security aspects of business continuity
- **A.17.1**: Planning information security continuity — backup/cron evidence
- **A.17.2**: Implementing information security continuity — rerun test in evidence
- **A.17.3**: ICT readiness for business continuity — session restore test

## A.18 — Compliance
- **A.18.1**: Compliance with legal and contractual requirements — export/report bundles
- **A.18.2**: Information security reviews — periodic audit schedule in cron
