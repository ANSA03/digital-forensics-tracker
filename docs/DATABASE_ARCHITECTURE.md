# PostgreSQL 17 Database Architecture & Engineering Guide

This document details the PostgreSQL 17 relational database implementation for the **Digital Forensics Evidence Tracker**, covering table structures, indexes, constraints, views, stored functions, and trigger-based audit trails.

---

## 1. Table Hierarchy & Relational Schema (12 Tables)

| # | Table Name | Purpose | Primary Key | Foreign Keys |
|---|---|---|---|---|
| 1 | `users` | Personnel accounts & RBAC | `user_id` | None |
| 2 | `investigations` | Case dossiers | `investigation_id` | `investigator_id` -> `users.user_id` |
| 3 | `evidence` | Digital & physical artifacts | `evidence_id` | `investigation_id`, `collected_by`, `current_custodian_id` |
| 4 | `chain_of_custody` | Custodial transfer ledger | `custody_id` | `evidence_id`, `transferred_from`, `transferred_to` |
| 5 | `integrity_checks` | SHA-256 verification history | `check_id` | `evidence_id`, `checked_by` |
| 6 | `audit_logs` | Trigger-generated audit stream | `log_id` | `user_id` |
| 7 | `tags` | Controlled taxonomy tags | `tag_id` | None |
| 8 | `evidence_tags` | Many-to-many tag mappings | `(evidence_id, tag_id)` | `evidence_id`, `tag_id`, `tagged_by` |
| 9 | `case_notes` | Investigative findings & notes | `note_id` | `investigation_id`, `author_id` |
| 10 | `forensic_tools` | NIST CFTT validated tool registry | `tool_id` | None |
| 11 | `evidence_tool_usage` | Tool execution logs | `usage_id` | `evidence_id`, `tool_id`, `operator_id` |
| 12 | `evidence_dispositions` | Legal retention/destruction | `disposition_id` | `evidence_id`, `requested_by`, `approved_by` |

---

## 2. Integrity Constraints & Performance Indexes

### Constraints
- `chk_evidence_sha256_format`: Validates that `sha256_hash` is either NULL or a strictly valid 64-character lowercase/uppercase hex string matching `^[a-f0-9]{64}$`.
- `users.email UNIQUE`: Guaranteed unique email addresses.
- `investigations.case_number UNIQUE`: Prevents duplicated case identifiers.
- `evidence.evidence_number UNIQUE`: Prevents duplicated evidence identifiers.

### Optimized Indexes
- `idx_evidence_investigation`: Fast lookups of evidence items per investigation.
- `idx_evidence_sha256`: Rapid query and comparison by cryptographic digest.
- `idx_evidence_status`: Accelerated filtering for compromised or verified artifacts.
- `idx_evidence_custodian`: Quick indexing of all evidence held by a specific officer.
- `idx_custody_evidence`: Retrieval of all transfers for an evidence piece.
- `idx_custody_transfer_date`: Chronological ordering of transfer ledger.
- `idx_integrity_evidence`: Timeline of integrity audits per artifact.
- `idx_audit_table_record`: Composite index for table name and record ID audit queries.
- `idx_audit_timestamp`: Reverse-chronological timeline of system mutations.

---

## 3. Analytical Views

The database defines four analytical views designed for reporting and high-speed dashboard analytics:

### 1. `v_evidence_custody_overview`
Joins evidence with investigation metadata, collector info, current custodian info, aggregated transfer counts, and the most recent SHA-256 integrity check result.

```sql
CREATE OR REPLACE VIEW v_evidence_custody_overview AS
SELECT 
    e.evidence_id, e.evidence_number, e.evidence_name, e.evidence_type,
    e.file_path, e.sha256_hash, e.file_size_bytes, e.status AS evidence_status,
    e.storage_location, e.collected_at, i.investigation_id, i.case_number,
    i.title AS case_title, i.status AS case_status,
    u_col.full_name AS collector_name,
    COALESCE(u_cust.full_name, u_col.full_name) AS current_custodian_name,
    COALESCE(cust_stat.total_transfers, 0) AS total_transfers,
    ic_latest.result AS last_check_result,
    ic_latest.checked_at AS last_check_date
FROM evidence e
JOIN investigations i ON e.investigation_id = i.investigation_id
JOIN users u_col ON e.collected_by = u_col.user_id
LEFT JOIN users u_cust ON e.current_custodian_id = u_cust.user_id
LEFT JOIN (
    SELECT evidence_id, COUNT(*) AS total_transfers
    FROM chain_of_custody
    GROUP BY evidence_id
) cust_stat ON e.evidence_id = cust_stat.evidence_id
LEFT JOIN (
    SELECT DISTINCT ON (evidence_id) evidence_id, result, checked_at
    FROM integrity_checks
    ORDER BY evidence_id, checked_at DESC
) ic_latest ON e.evidence_id = ic_latest.evidence_id;
```

### 2. `v_investigation_metrics`
Aggregates active metrics per case: total evidence, verified count, compromised count, custody transfer count, notes count, and active elapsed days.

### 3. `v_chain_of_custody_timeline`
Chronological view of all custody transfers enriched with sender and receiver identities, badges, transfer reasons, and location data.

### 4. `v_tamper_incident_summary`
Filters all compromised artifacts and `TAMPERED` integrity checks into an active security incident view.

---

## 4. Stored Procedures and Functions (PL/pgSQL)

### 1. `fn_transfer_evidence_custody`
- **Parameters**: `p_evidence_id`, `p_from_user`, `p_to_user`, `p_purpose`, `p_location`, `p_auth_notes`
- **Behavior**:
  - Validates evidence existence.
  - Validates that `p_from_user` is the designated custodian (or original collector).
  - Inserts the new transfer into `chain_of_custody`.
  - Updates `evidence.current_custodian_id`, `storage_location`, and status.
  - Returns a JSONB response with `success` flag and `custody_id`.

### 2. `fn_verify_evidence_integrity`
- **Parameters**: `p_evidence_id`, `p_checked_by`, `p_calculated_hash`, `p_notes`
- **Behavior**:
  - Compares the baseline `sha256_hash` against `p_calculated_hash`.
  - If equal: marks result as `VERIFIED` and sets evidence status to `Verified`.
  - If mismatch: marks result as `TAMPERED`, sets evidence status to `Compromised`.
  - Inserts row into `integrity_checks`.
  - Returns JSONB with validation breakdown.

### 3. `fn_get_case_summary`
- **Parameters**: `p_case_id`
- **Behavior**: Generates aggregated case metrics directly in the database engine and returns them as structured JSON.

---

## 5. Automated Audit Logging via PostgreSQL Triggers

The system implements automated audit tracking via the trigger function `trg_audit_trail()`.

### Trigger Function Behavior:
- Captures operations (`INSERT`, `UPDATE`, `DELETE`) on `evidence`, `investigations`, `chain_of_custody`, `integrity_checks`, `case_notes`, and `evidence_dispositions`.
- Encodes state diffs as JSON:
  - On `INSERT`: Captures key field values and initial state.
  - On `UPDATE`: Captures previous values vs new values (e.g. status transition, custodian transfer).
  - On `DELETE`: Captures the deleted row snapshot.
- Directly inserts into `audit_logs` inside the same transaction, guaranteeing that any modification creates an unalterable audit trail regardless of whether it originates from the web UI, an API, or direct SQL execution.
