# ISO 27001:2022 Annex A Controls — Agent Mapping

Agent-relevant controls and how Hermes logs map to them.

## A.5 — Information security policies
| Control | Agent event |
|---------|-------------|
| A.5.1 Policies for information security | `on_config_change` |
| A.5.2 Information security roles and responsibilities | session start/end |

## A.6 — Organization of information security
| Control | Agent event |
|---------|-------------|
| A.6.1 Internal organization | skill/plugin install events |
| A.6.2 Mobile devices and teleworking | terminal backend changes |

## A.7 — Human resource security
| Control | Agent event |
|---------|-------------|
| A.7.3 Awareness, education and training | `/iso27k report --control A.7` |

## A.8 — Access control
| Control | Agent event |
|---------|-------------|
| A.8.2 User access management | terminal/file tool access |
| A.8.3 Information access restriction | `read_file`, `write_file` path coverage |
| A.8.5 Secure authentication | `.env`/config changes |

## A.9 — Cryptography
| Control | Agent event |
|---------|-------------|
| A.9.4 Cryptography usage | secret access events |

## A.12 — Operations security
| Control | Agent event |
|---------|-------------|
| A.12.1 Documented operating procedures | `on_config_change` |
| A.12.3 Capacity management | cron job changes |
| A.12.4 Separation of development/test/production | session boundaries |
| A.12.6 Management of technical vulnerabilities | plugin/skill updates |

## A.14 — System acquisition/development/maintenance
| Control | Agent event |
|---------|-------------|
| A.14.2 Security in development and support processes | skill mutations, plugin installs |
| A.14.2.5 Secure coding policy | `post_tool_call` for code writes |

## A.15 — Supplier relationships
| Control | Agent event |
|---------|-------------|
| A.15.2.1 Supplier relationship security policy | MCP server additions |

## A.16 — Information security incident management
| Control | Agent event |
|---------|-------------|
| A.16.1 Management of information security incidents and improvements | policy violation alerts |

## A.17 — Information security aspects of business continuity
| Control | Agent event |
|---------|-------------|
| A.17.1 Planning information security continuity | backup/cron review |

## A.18 — Compliance
| Control | Agent event |
|---------|-------------|
| A.18.1 Compliance with legal and contractual requirements | export/report bundles |
