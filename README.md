# Aegis Digital Forensics Evidence Tracker

A full-stack, enterprise-grade digital forensics evidence and chain-of-custody tracking platform built with **Python Flask** and **PostgreSQL 17**. 

Engineered for cyber incident response teams, digital forensics laboratories, law enforcement task forces, and compliance auditors adhering to the **Federal Rules of Evidence (Rule 902(14))**, **ISO/IEC 27037**, and **NIST CFTT** standards.

---

## 🌟 Key Capabilities & Features

1. **Role-Based Access Control (RBAC)**:
   - Four distinct clearance tiers: `Admin`, `Lead Investigator`, `Forensic Analyst`, and `Auditor`.
   - Salted and hashed authentication with `bcrypt`.
   - Session isolation and administrative user role management.

2. **Investigation Dossier Management**:
   - Case creation, multi-attribute search, priority scoring (`Critical`, `High`, `Medium`, `Low`), and status tracking.
   - Comprehensive case workspace with attached evidence, investigator notes, and timeline logs.
   - Database-level summary exports via PostgreSQL stored functions.

3. **Digital Evidence Intake & File Ingestion**:
   - Evidence registry supporting disk images, memory dumps, network PCAPs, mobile extractions, and cloud snapshots.
   - Secure drag-and-drop file upload with streaming SHA-256 calculation chunk-by-chunk.
   - Safe storage naming (UUID prefix) with MIME type detection and file size tracking.

4. **Cryptographic Integrity & Tamper Detection**:
   - Baseline SHA-256 digest preservation with one-click clipboard copying.
   - On-demand cryptographic re-verification against stored binary files on disk.
   - **Simulate Tamper Detection**: Built-in verification testing feature that simulates an altered payload, confirms instant detection, transitions status to `Compromised`, and raises a prominent visual alert.

5. **Chain-of-Custody Tracking with PostgreSQL Transactions**:
   - Strictly enforced custody transfer transactions: sender must be the designated custodian.
   - Transactional rollback on error to ensure an unbroken chain of custody.
   - Printable, court-admissible Chain of Custody manifests with witness and custodian signature blocks.

6. **Automatic Audit Logging via PostgreSQL Triggers**:
   - Database triggers (`AFTER INSERT OR UPDATE OR DELETE`) on all critical tables.
   - Automatically serializes JSON before/after state diffs directly to the `audit_logs` table.
   - Guarantees tamper-proof logging even for direct SQL mutations.

7. **Dark Forensics Operations Dashboard**:
   - Custom high-contrast cybersecurity dark theme with responsive sidebar and metrics.
   - 4 interactive **Chart.js** visualizations:
     - Evidence Classification Distribution (Doughnut)
     - Investigations by Status (Bar)
     - Cryptographic Integrity Status (Pie)
     - Chain of Custody Activity (Line/Timeline)

8. **Relational Database Model (12 Normalized Tables)**:
   - `users`, `investigations`, `evidence`, `chain_of_custody`, `integrity_checks`, `audit_logs`, `tags`, `evidence_tags`, `case_notes`, `forensic_tools`, `evidence_tool_usage`, `evidence_dispositions`.

9. **Advanced SQL Features**:
   - 4 Analytical Views: `v_evidence_custody_overview`, `v_investigation_metrics`, `v_chain_of_custody_timeline`, `v_tamper_incident_summary`.
   - 3 Stored Functions: `fn_transfer_evidence_custody`, `fn_verify_evidence_integrity`, `fn_get_case_summary`.
   - Hex-format `CHECK` constraints on SHA-256 digests.
   - Optimized B-tree composite and foreign key indexes.

10. **Automated Test Suite & Documentation**:
    - Comprehensive unit test suite covering health, auth, RBAC, cases, uploads, hashing, tamper detection, transactions, and triggers.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.14 / 3.11+, Flask 3.1, Flask-SQLAlchemy 3.1, SQLAlchemy 2.0
- **Database**: PostgreSQL 17 (Homebrew / Native)
- **Database Driver**: `psycopg2-binary`
- **Security & Cryptography**: `bcrypt`, `hashlib` (SHA-256), `Werkzeug`
- **Frontend**: Semantic HTML5, Vanilla JavaScript, CSS3 Dark Operations Theme, Chart.js 4.4

---

## 👥 Demo Personnel Accounts

The application includes seeded demo personnel accounts across all four operational tiers:

| Role | Email | Password | Badge Number | Department |
|---|---|---|---|---|
| **Admin** | `admin@forensics.local` | `AdminSecure123!` | `DF-001` | Cyber Directorate Executive |
| **Lead Investigator** | `alex.cross@forensics.local` | `Investigator123!` | `DF-104` | Major Cyber Incidents Taskforce |
| **Forensic Analyst** | `elena.rostova@forensics.local` | `Analyst123!` | `DF-205` | Digital Evidence Lab |
| **Auditor** | `marcus.sterling@forensics.local` | `Auditor123!` | `DF-901` | Office of Inspector General |

*(The login page features a one-click demo credentials helper.)*

---

## 🚀 Quickstart Guide

### 1. Environment Setup
Ensure virtual environment dependencies are installed:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)
Verify `.env` has your local PostgreSQL 17 connection string:
```bash
SECRET_KEY=your-secure-secret-key
DATABASE_URL=postgresql://ansan@localhost:5432/digital_forensics_db
```

### 3. Apply Schema Migrations
Execute the safe schema enhancement script (creates all tables, triggers, functions, views, and indexes without deleting existing data):
```bash
python migrate.py
```

### 4. Seed Initial Data
Seed initial users, forensic tools, sample cases, and baseline evidence:
```bash
python seed_data.py
```

### 5. Run the Application
Launch the Flask development server:
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 🧪 Running Automated Tests

Run the full automated test suite verifying all 10 core components:
```bash
python -m unittest tests/test_tracker.py -v
```

All 10 tests will execute against the PostgreSQL database:
- `test_01_health_check`
- `test_02_authentication_and_rbac`
- `test_03_investigation_management`
- `test_04_evidence_registration_and_hashing`
- `test_05_integrity_verification_and_tamper_detection`
- `test_06_chain_of_custody_transactions`
- `test_07_postgresql_trigger_audit_logging`
- `test_08_sql_views_and_functions`
- `test_09_dashboard_stats_api`
- `test_10_tools_and_dispositions`

---

## 📁 Project Directory Structure

```
digital-forensics-tracker/
├── app.py                     # Main Flask application & route controllers
├── models.py                  # SQLAlchemy models (all 12 relational tables)
├── config.py                  # Application configuration & upload constraints
├── migrate.py                 # PostgreSQL migration executor
├── seed_data.py               # Seed script with realistic forensic test data
├── requirements.txt           # Pinned dependencies
├── .gitignore                 # Excludes .env, venv/, and uploads/
├── migrations/
│   └── 001_complete_forensics_schema.sql  # Safe SQL DDL, views, triggers & functions
├── docs/
│   ├── ER_DIAGRAM.md          # Full Mermaid ER diagram & relationships
│   └── DATABASE_ARCHITECTURE.md # PostgreSQL 17 deep architectural reference
├── tests/
│   └── test_tracker.py        # Automated test suite
├── static/
│   ├── css/
│   │   └── style.css          # Dark forensics operations stylesheet
│   └── js/
│       └── main.js            # Chart.js initialization, dropzone, table search
├── templates/
│   ├── base.html              # Shell layout with responsive navigation
│   ├── login.html             # Authentication portal with demo picker
│   ├── register.html          # Investigator registration
│   ├── dashboard.html         # Metrics cards & 4 Chart.js charts
│   ├── cases.html             # Investigation dossiers registry
│   ├── case_form.html         # Case creation and editing
│   ├── case_detail.html       # Case workspace with notes & evidence
│   ├── evidence.html          # Digital evidence registry
│   ├── add_evidence.html      # Evidence registration & file upload
│   ├── evidence_detail.html   # Evidence detail & SHA-256 verification
│   ├── custody.html           # Chain of custody hub & transfer form
│   ├── custody_report.html    # Court-admissible printable manifest
│   ├── tools.html             # Validated forensic tools inventory
│   ├── dispositions.html      # Evidence retention & destruction orders
│   ├── audit_logs.html        # Trigger-generated audit log viewer
│   └── users.html             # User administration & role management
└── uploads/
    └── evidence/              # Secure on-disk binary evidence storage
```

---

## 🔒 Security & Forensic Admissibility Standards

- **Append-Only Custody Log**: Custody transfer records cannot be updated or deleted through standard interfaces.
- **Pl/pgSQL Atomic Execution**: Custody transfers occur within an atomic database function; failures rollback immediately with no orphaned data.
- **Trigger-Level Audit Trail**: Every database mutation (`INSERT`, `UPDATE`, `DELETE`) is captured by `trg_audit_trail()` and written directly to `audit_logs`.
- **Cryptographic Hashing**: Evidence files are hashed at intake using streaming SHA-256 blocks; any alteration of bytes on disk or in the database triggers immediate tamper detection.
