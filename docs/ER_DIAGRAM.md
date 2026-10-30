# Digital Forensics Evidence Tracker - Entity Relationship Diagram

This document illustrates the complete relational database architecture consisting of 12 core tables powering the Digital Forensics Evidence Tracker in PostgreSQL 17.

```mermaid
erDiagram
    users ||--o{ investigations : "leads"
    users ||--o{ evidence : "collects"
    users ||--o{ evidence : "holds custody of"
    users ||--o{ chain_of_custody : "transfers from"
    users ||--o{ chain_of_custody : "transfers to"
    users ||--o{ integrity_checks : "performs"
    users ||--o{ audit_logs : "triggers"
    users ||--o{ case_notes : "authors"
    users ||--o{ evidence_tool_usage : "operates"
    users ||--o{ evidence_dispositions : "requests"
    users ||--o{ evidence_dispositions : "approves"

    investigations ||--o{ evidence : "contains"
    investigations ||--o{ case_notes : "logs"

    evidence ||--o{ chain_of_custody : "tracks"
    evidence ||--o{ integrity_checks : "verifies"
    evidence ||--o{ evidence_tags : "categorized by"
    evidence ||--o{ evidence_tool_usage : "analyzed with"
    evidence ||--o{ evidence_dispositions : "disposed by"

    tags ||--o{ evidence_tags : "labels"
    forensic_tools ||--o{ evidence_tool_usage : "applied in"

    users {
        int user_id PK
        string full_name
        string email UK
        string password_hash
        string role
        string badge_number
        string department
        boolean is_active
        timestamptz created_at
    }

    investigations {
        int investigation_id PK
        string case_number UK
        string title
        text description
        string status
        string priority
        int investigator_id FK
        timestamptz incident_date
        timestamptz created_at
        timestamptz closed_at
    }

    evidence {
        int evidence_id PK
        string evidence_number UK
        string evidence_name
        string evidence_type
        text description
        string file_path
        string original_filename
        bigint file_size_bytes
        string mime_type
        string sha256_hash
        string status
        string storage_location
        int investigation_id FK
        int collected_by FK
        int current_custodian_id FK
        timestamptz collected_at
    }

    chain_of_custody {
        int custody_id PK
        int evidence_id FK
        int transferred_from FK
        int transferred_to FK
        timestamptz transfer_date
        text purpose
        string location
        text authorization_notes
    }

    integrity_checks {
        int check_id PK
        int evidence_id FK
        int checked_by FK
        string original_hash
        string calculated_hash
        string result
        text notes
        timestamptz checked_at
    }

    audit_logs {
        int log_id PK
        int user_id FK
        string action
        string table_name
        int record_id
        text details
        string ip_address
        timestamptz timestamp
    }

    tags {
        int tag_id PK
        string name UK
        string description
        string color_code
        timestamptz created_at
    }

    evidence_tags {
        int evidence_id PK,FK
        int tag_id PK,FK
        int tagged_by FK
        timestamptz tagged_at
    }

    case_notes {
        int note_id PK
        int investigation_id FK
        int author_id FK
        string note_type
        string title
        text content
        boolean is_confidential
        timestamptz created_at
        timestamptz updated_at
    }

    forensic_tools {
        int tool_id PK
        string name
        string version
        string vendor
        string tool_type
        boolean is_validated
        date validation_date
        text notes
        timestamptz created_at
    }

    evidence_tool_usage {
        int usage_id PK
        int evidence_id FK
        int tool_id FK
        int operator_id FK
        string action_type
        text command_executed
        text output_summary
        timestamptz used_at
    }

    evidence_dispositions {
        int disposition_id PK
        int evidence_id FK
        int requested_by FK
        int approved_by FK
        string disposition_type
        string status
        text reason
        string legal_authorization
        timestamptz completed_at
        timestamptz created_at
    }
```

## Relational Summary

1. **`users`**: Personnel directory storing hashed credentials, roles, badges, and department affiliations.
2. **`investigations`**: Top-level case dossiers with priority levels, lifecycle statuses, and incident timelines.
3. **`evidence`**: Registered physical and digital artifacts with streaming SHA-256 baseline hashes and dual custodian bindings.
4. **`chain_of_custody`**: Append-only transactional transfer ledger maintaining unbroken legal custody under Federal Rules of Evidence.
5. **`integrity_checks`**: On-demand and periodic cryptographic verification audits verifying artifact hash integrity.
6. **`audit_logs`**: System audit trail populated automatically via PostgreSQL 17 triggers on data mutations.
7. **`tags`**: Controlled forensic taxonomy (e.g. Malware, Volatile Memory, Network PCAP).
8. **`evidence_tags`**: Associative junction table linking artifacts with classification tags.
9. **`case_notes`**: Chronological investigative observations, findings, and hypotheses with optional confidentiality flags.
10. **`forensic_tools`**: Inventory of NIST CFTT validated hardware write-blockers and software suites.
11. **`evidence_tool_usage`**: Scientific reproducibility logs detailing every tool invocation on evidence.
12. **`evidence_dispositions`**: Controlled disposition requests (retention, destruction, court presentation) requiring two-party signoff.
