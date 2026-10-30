-- ==============================================================================
-- Digital Forensics Evidence Tracker - Database Migration 001
-- PostgreSQL 17 Compatible Schema Enhancement
-- Preserves existing tables/data while adding 6 new tables, views, stored
-- functions, indexes, and automated audit triggers.
-- ==============================================================================

-- 1. Enhance Existing Tables Safely
-- ------------------------------------------------------------------------------
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS badge_number VARCHAR(50),
    ADD COLUMN IF NOT EXISTS department VARCHAR(100),
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

ALTER TABLE investigations
    ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'Medium',
    ADD COLUMN IF NOT EXISTS incident_date TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

ALTER TABLE evidence
    ADD COLUMN IF NOT EXISTS file_size_bytes BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mime_type VARCHAR(100),
    ADD COLUMN IF NOT EXISTS original_filename VARCHAR(255),
    ADD COLUMN IF NOT EXISTS current_custodian_id INTEGER REFERENCES users(user_id),
    ADD COLUMN IF NOT EXISTS storage_location VARCHAR(200) DEFAULT 'Evidence Locker A-1';

ALTER TABLE chain_of_custody
    ADD COLUMN IF NOT EXISTS authorization_notes TEXT;

ALTER TABLE integrity_checks
    ADD COLUMN IF NOT EXISTS notes TEXT;

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS ip_address VARCHAR(50);


-- 2. Create Additional Meaningful Forensic Tables (12 Total System Tables)
-- ------------------------------------------------------------------------------

-- Table 7: Evidence Tags (Categorization for forensic classification)
CREATE TABLE IF NOT EXISTS tags (
    tag_id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(200),
    color_code VARCHAR(20) DEFAULT '#38bdf8',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table 8: Evidence-to-Tag Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS evidence_tags (
    evidence_id INTEGER NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE,
    tagged_by INTEGER REFERENCES users(user_id),
    tagged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (evidence_id, tag_id)
);

-- Table 9: Investigation Case Notes & Findings
CREATE TABLE IF NOT EXISTS case_notes (
    note_id SERIAL PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(user_id),
    note_type VARCHAR(50) NOT NULL DEFAULT 'Forensic Observation',
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    is_confidential BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table 10: Forensic Tools Registry (Hardware write blockers, imaging/analysis software)
CREATE TABLE IF NOT EXISTS forensic_tools (
    tool_id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    version VARCHAR(50) NOT NULL,
    vendor VARCHAR(150),
    tool_type VARCHAR(50) NOT NULL,
    is_validated BOOLEAN DEFAULT TRUE,
    validation_date DATE DEFAULT CURRENT_DATE,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table 11: Evidence Tool Usage Records (Audit for forensics methodology)
CREATE TABLE IF NOT EXISTS evidence_tool_usage (
    usage_id SERIAL PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    tool_id INTEGER NOT NULL REFERENCES forensic_tools(tool_id) ON DELETE RESTRICT,
    operator_id INTEGER NOT NULL REFERENCES users(user_id),
    action_type VARCHAR(100) NOT NULL,
    command_executed TEXT,
    output_summary TEXT,
    used_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table 12: Evidence Disposition & Court Presentation Tracking
CREATE TABLE IF NOT EXISTS evidence_dispositions (
    disposition_id SERIAL PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    requested_by INTEGER NOT NULL REFERENCES users(user_id),
    approved_by INTEGER REFERENCES users(user_id),
    disposition_type VARCHAR(50) NOT NULL,
    status VARCHAR(30) DEFAULT 'Pending',
    reason TEXT NOT NULL,
    legal_authorization VARCHAR(200),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


-- 3. Constraints and Optimized Indexes
-- ------------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_evidence_sha256_format'
    ) THEN
        ALTER TABLE evidence 
            ADD CONSTRAINT chk_evidence_sha256_format 
            CHECK (sha256_hash IS NULL OR sha256_hash ~* '^[a-f0-9]{64}$');
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
CREATE INDEX IF NOT EXISTS idx_evidence_custodian ON evidence(current_custodian_id);

CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_transfer_date ON chain_of_custody(transfer_date DESC);
CREATE INDEX IF NOT EXISTS idx_custody_transferred_to ON chain_of_custody(transferred_to);

CREATE INDEX IF NOT EXISTS idx_integrity_evidence ON integrity_checks(evidence_id);
CREATE INDEX IF NOT EXISTS idx_integrity_checked_at ON integrity_checks(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_result ON integrity_checks(result);

CREATE INDEX IF NOT EXISTS idx_audit_table_record ON audit_logs(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_case_notes_investigation ON case_notes(investigation_id);
CREATE INDEX IF NOT EXISTS idx_tool_usage_evidence ON evidence_tool_usage(evidence_id);
CREATE INDEX IF NOT EXISTS idx_dispositions_evidence ON evidence_dispositions(evidence_id);


-- 4. Analytical Views for Reporting and Dashboard
-- ------------------------------------------------------------------------------

-- View 1: Evidence Custody & Integrity Overview
CREATE OR REPLACE VIEW v_evidence_custody_overview AS
SELECT 
    e.evidence_id,
    e.evidence_number,
    e.evidence_name,
    e.evidence_type,
    e.file_path,
    e.sha256_hash,
    e.file_size_bytes,
    e.status AS evidence_status,
    e.storage_location,
    e.collected_at,
    i.investigation_id,
    i.case_number,
    i.title AS case_title,
    i.status AS case_status,
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
    SELECT DISTINCT ON (evidence_id) 
        evidence_id, result, checked_at
    FROM integrity_checks
    ORDER BY evidence_id, checked_at DESC
) ic_latest ON e.evidence_id = ic_latest.evidence_id;

-- View 2: Investigation Case Metrics
CREATE OR REPLACE VIEW v_investigation_metrics AS
SELECT 
    i.investigation_id,
    i.case_number,
    i.title,
    i.status,
    i.priority,
    i.created_at,
    i.closed_at,
    u.full_name AS lead_investigator,
    COUNT(DISTINCT e.evidence_id) AS total_evidence,
    COUNT(DISTINCT CASE WHEN e.status = 'Verified' THEN e.evidence_id END) AS verified_evidence,
    COUNT(DISTINCT CASE WHEN e.status = 'Compromised' THEN e.evidence_id END) AS compromised_evidence,
    COUNT(DISTINCT coc.custody_id) AS total_custody_transfers,
    COUNT(DISTINCT cn.note_id) AS total_notes,
    EXTRACT(DAY FROM (COALESCE(i.closed_at, CURRENT_TIMESTAMP) - i.created_at))::INT AS days_active
FROM investigations i
JOIN users u ON i.investigator_id = u.user_id
LEFT JOIN evidence e ON i.investigation_id = e.investigation_id
LEFT JOIN chain_of_custody coc ON e.evidence_id = coc.evidence_id
LEFT JOIN case_notes cn ON i.investigation_id = cn.investigation_id
GROUP BY i.investigation_id, i.case_number, i.title, i.status, i.priority, i.created_at, i.closed_at, u.full_name;

-- View 3: Complete Chain of Custody Chronological Timeline
CREATE OR REPLACE VIEW v_chain_of_custody_timeline AS
SELECT 
    coc.custody_id,
    coc.evidence_id,
    e.evidence_number,
    e.evidence_name,
    i.case_number,
    u_from.full_name AS transferred_from_name,
    u_from.badge_number AS transferred_from_badge,
    u_to.full_name AS transferred_to_name,
    u_to.badge_number AS transferred_to_badge,
    coc.transfer_date,
    coc.purpose,
    coc.location,
    coc.authorization_notes
FROM chain_of_custody coc
JOIN evidence e ON coc.evidence_id = e.evidence_id
JOIN investigations i ON e.investigation_id = i.investigation_id
JOIN users u_from ON coc.transferred_from = u_from.user_id
JOIN users u_to ON coc.transferred_to = u_to.user_id
ORDER BY coc.transfer_date DESC;

-- View 4: Evidence Tamper Alert & Integrity Failure Summary
CREATE OR REPLACE VIEW v_tamper_incident_summary AS
SELECT 
    ic.check_id,
    ic.evidence_id,
    e.evidence_number,
    e.evidence_name,
    i.case_number,
    i.title AS case_title,
    u.full_name AS checked_by_name,
    ic.original_hash,
    ic.calculated_hash,
    ic.result,
    ic.notes,
    ic.checked_at,
    e.storage_location,
    e.file_path
FROM integrity_checks ic
JOIN evidence e ON ic.evidence_id = e.evidence_id
JOIN investigations i ON e.investigation_id = i.investigation_id
JOIN users u ON ic.checked_by = u.user_id
WHERE ic.result = 'TAMPERED' OR e.status = 'Compromised'
ORDER BY ic.checked_at DESC;


-- 5. Stored Procedures and Functions for Business Logic & Transactions
-- ------------------------------------------------------------------------------

-- Function 1: Atomic Chain of Custody Transfer
CREATE OR REPLACE FUNCTION fn_transfer_evidence_custody(
    p_evidence_id INTEGER,
    p_from_user INTEGER,
    p_to_user INTEGER,
    p_purpose TEXT,
    p_location VARCHAR(200),
    p_auth_notes TEXT DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_current_custodian INTEGER;
    v_collector INTEGER;
    v_evidence_status VARCHAR(30);
    v_custody_id INTEGER;
BEGIN
    -- Check if evidence exists and get current status
    SELECT current_custodian_id, collected_by, status
    INTO v_current_custodian, v_collector, v_evidence_status
    FROM evidence
    WHERE evidence_id = p_evidence_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'message', 'Evidence item not found'
        );
    END IF;

    -- Validate sender: must be the current custodian (or collector if no custodian set)
    IF v_current_custodian IS NOT NULL THEN
        IF v_current_custodian <> p_from_user THEN
            RETURN jsonb_build_object(
                'success', false,
                'message', 'Transfer denied: sender is not the designated custodian of this evidence'
            );
        END IF;
    ELSE
        IF v_collector <> p_from_user THEN
            RETURN jsonb_build_object(
                'success', false,
                'message', 'Transfer denied: sender is not the original collector of this evidence'
            );
        END IF;
    END IF;

    -- Insert chain of custody record
    INSERT INTO chain_of_custody (
        evidence_id, transferred_from, transferred_to, transfer_date, purpose, location, authorization_notes
    ) VALUES (
        p_evidence_id, p_from_user, p_to_user, CURRENT_TIMESTAMP, p_purpose, p_location, p_auth_notes
    ) RETURNING custody_id INTO v_custody_id;

    -- Update evidence current custodian and location
    UPDATE evidence
    SET current_custodian_id = p_to_user,
        storage_location = COALESCE(p_location, storage_location),
        status = CASE WHEN status = 'Compromised' THEN 'Compromised' ELSE 'In Custody' END
    WHERE evidence_id = p_evidence_id;

    RETURN jsonb_build_object(
        'success', true,
        'custody_id', v_custody_id,
        'message', 'Chain of custody recorded successfully'
    );
END;
$$ LANGUAGE plpgsql;

-- Function 2: Atomic Evidence Integrity Verification & Tamper Detection
CREATE OR REPLACE FUNCTION fn_verify_evidence_integrity(
    p_evidence_id INTEGER,
    p_checked_by INTEGER,
    p_calculated_hash VARCHAR(64),
    p_notes TEXT DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_original_hash VARCHAR(64);
    v_result VARCHAR(20);
    v_check_id INTEGER;
    v_is_match BOOLEAN;
BEGIN
    SELECT sha256_hash INTO v_original_hash
    FROM evidence
    WHERE evidence_id = p_evidence_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'message', 'Evidence not found'
        );
    END IF;

    v_is_match := (LOWER(TRIM(v_original_hash)) = LOWER(TRIM(p_calculated_hash)));

    IF v_is_match THEN
        v_result := 'VERIFIED';
        UPDATE evidence 
        SET status = 'Verified'
        WHERE evidence_id = p_evidence_id AND status <> 'Compromised';
    ELSE
        v_result := 'TAMPERED';
        UPDATE evidence 
        SET status = 'Compromised'
        WHERE evidence_id = p_evidence_id;
    END IF;

    INSERT INTO integrity_checks (
        evidence_id, checked_by, original_hash, calculated_hash, result, notes, checked_at
    ) VALUES (
        p_evidence_id, p_checked_by, v_original_hash, p_calculated_hash, v_result, p_notes, CURRENT_TIMESTAMP
    ) RETURNING check_id INTO v_check_id;

    RETURN jsonb_build_object(
        'success', true,
        'check_id', v_check_id,
        'result', v_result,
        'is_match', v_is_match,
        'original_hash', v_original_hash,
        'calculated_hash', p_calculated_hash
    );
END;
$$ LANGUAGE plpgsql;

-- Function 3: Comprehensive Case Forensic Statistics
CREATE OR REPLACE FUNCTION fn_get_case_summary(p_case_id INTEGER)
RETURNS JSONB AS $$
DECLARE
    v_summary JSONB;
BEGIN
    SELECT jsonb_build_object(
        'investigation_id', i.investigation_id,
        'case_number', i.case_number,
        'title', i.title,
        'status', i.status,
        'priority', i.priority,
        'investigator', u.full_name,
        'total_evidence', COUNT(DISTINCT e.evidence_id),
        'verified_evidence', COUNT(DISTINCT CASE WHEN e.status = 'Verified' THEN e.evidence_id END),
        'compromised_evidence', COUNT(DISTINCT CASE WHEN e.status = 'Compromised' THEN e.evidence_id END),
        'custody_transfers', COUNT(DISTINCT coc.custody_id),
        'case_notes_count', COUNT(DISTINCT cn.note_id)
    ) INTO v_summary
    FROM investigations i
    JOIN users u ON i.investigator_id = u.user_id
    LEFT JOIN evidence e ON i.investigation_id = e.investigation_id
    LEFT JOIN chain_of_custody coc ON e.evidence_id = coc.evidence_id
    LEFT JOIN case_notes cn ON i.investigation_id = cn.investigation_id
    WHERE i.investigation_id = p_case_id
    GROUP BY i.investigation_id, i.case_number, i.title, i.status, i.priority, u.full_name;

    RETURN v_summary;
END;
$$ LANGUAGE plpgsql;


-- 6. PostgreSQL Trigger-based Automated Audit Logging
-- ------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION trg_audit_trail()
RETURNS TRIGGER AS $$
DECLARE
    v_record_id INTEGER;
    v_details TEXT;
    v_user_id INTEGER := NULL;
    v_action TEXT;
BEGIN
    -- Read optional session-level user ID if set by application
    BEGIN
        v_user_id := NULLIF(current_setting('app.current_user_id', true), '')::INTEGER;
    EXCEPTION WHEN OTHERS THEN
        v_user_id := NULL;
    END;

    IF TG_OP = 'INSERT' THEN
        v_action := 'INSERT';
        IF TG_TABLE_NAME = 'evidence' THEN
            v_record_id := NEW.evidence_id;
            v_details := json_build_object(
                'evidence_number', NEW.evidence_number,
                'name', NEW.evidence_name,
                'type', NEW.evidence_type,
                'sha256', NEW.sha256_hash,
                'status', NEW.status
            )::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.collected_by; END IF;
        ELSIF TG_TABLE_NAME = 'investigations' THEN
            v_record_id := NEW.investigation_id;
            v_details := json_build_object(
                'case_number', NEW.case_number,
                'title', NEW.title,
                'status', NEW.status,
                'priority', NEW.priority
            )::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.investigator_id; END IF;
        ELSIF TG_TABLE_NAME = 'chain_of_custody' THEN
            v_record_id := NEW.custody_id;
            v_details := json_build_object(
                'evidence_id', NEW.evidence_id,
                'from_user', NEW.transferred_from,
                'to_user', NEW.transferred_to,
                'purpose', NEW.purpose,
                'location', NEW.location
            )::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.transferred_from; END IF;
        ELSIF TG_TABLE_NAME = 'integrity_checks' THEN
            v_record_id := NEW.check_id;
            v_details := json_build_object(
                'evidence_id', NEW.evidence_id,
                'result', NEW.result,
                'original_hash', NEW.original_hash,
                'calculated_hash', NEW.calculated_hash
            )::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.checked_by; END IF;
        ELSIF TG_TABLE_NAME = 'case_notes' THEN
            v_record_id := NEW.note_id;
            v_details := json_build_object('investigation_id', NEW.investigation_id, 'title', NEW.title)::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.author_id; END IF;
        ELSIF TG_TABLE_NAME = 'evidence_dispositions' THEN
            v_record_id := NEW.disposition_id;
            v_details := json_build_object('evidence_id', NEW.evidence_id, 'type', NEW.disposition_type, 'status', NEW.status)::text;
            IF v_user_id IS NULL THEN v_user_id := NEW.requested_by; END IF;
        ELSE
            v_details := row_to_json(NEW)::text;
        END IF;

    ELSIF TG_OP = 'UPDATE' THEN
        v_action := 'UPDATE';
        IF TG_TABLE_NAME = 'evidence' THEN
            v_record_id := NEW.evidence_id;
            v_details := json_build_object(
                'evidence_number', NEW.evidence_number,
                'status_old', OLD.status,
                'status_new', NEW.status,
                'custodian_old', OLD.current_custodian_id,
                'custodian_new', NEW.current_custodian_id,
                'location_old', OLD.storage_location,
                'location_new', NEW.storage_location
            )::text;
        ELSIF TG_TABLE_NAME = 'investigations' THEN
            v_record_id := NEW.investigation_id;
            v_details := json_build_object(
                'case_number', NEW.case_number,
                'status_old', OLD.status,
                'status_new', NEW.status,
                'priority_old', OLD.priority,
                'priority_new', NEW.priority
            )::text;
        ELSIF TG_TABLE_NAME = 'evidence_dispositions' THEN
            v_record_id := NEW.disposition_id;
            v_details := json_build_object('status_old', OLD.status, 'status_new', NEW.status, 'approved_by', NEW.approved_by)::text;
        ELSE
            v_details := json_build_object('old', row_to_json(OLD), 'new', row_to_json(NEW))::text;
        END IF;

    ELSIF TG_OP = 'DELETE' THEN
        v_action := 'DELETE';
        IF TG_TABLE_NAME = 'evidence' THEN
            v_record_id := OLD.evidence_id;
            v_details := json_build_object('evidence_number', OLD.evidence_number, 'name', OLD.evidence_name)::text;
        ELSIF TG_TABLE_NAME = 'investigations' THEN
            v_record_id := OLD.investigation_id;
            v_details := json_build_object('case_number', OLD.case_number, 'title', OLD.title)::text;
        ELSIF TG_TABLE_NAME = 'case_notes' THEN
            v_record_id := OLD.note_id;
            v_details := json_build_object('investigation_id', OLD.investigation_id, 'title', OLD.title)::text;
        ELSIF TG_TABLE_NAME = 'chain_of_custody' THEN
            v_record_id := OLD.custody_id;
            v_details := json_build_object('evidence_id', OLD.evidence_id)::text;
        ELSIF TG_TABLE_NAME = 'integrity_checks' THEN
            v_record_id := OLD.check_id;
            v_details := json_build_object('evidence_id', OLD.evidence_id)::text;
        ELSIF TG_TABLE_NAME = 'evidence_dispositions' THEN
            v_record_id := OLD.disposition_id;
            v_details := json_build_object('evidence_id', OLD.evidence_id, 'type', OLD.disposition_type)::text;
        ELSE
            v_details := row_to_json(OLD)::text;
        END IF;
    END IF;

    INSERT INTO audit_logs (user_id, action, table_name, record_id, details, timestamp)
    VALUES (v_user_id, v_action, TG_TABLE_NAME, v_record_id, v_details, CURRENT_TIMESTAMP);

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Bind triggers to critical forensic tables
DROP TRIGGER IF EXISTS trg_evidence_audit ON evidence;
CREATE TRIGGER trg_evidence_audit
AFTER INSERT OR UPDATE OR DELETE ON evidence
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();

DROP TRIGGER IF EXISTS trg_investigations_audit ON investigations;
CREATE TRIGGER trg_investigations_audit
AFTER INSERT OR UPDATE OR DELETE ON investigations
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();

DROP TRIGGER IF EXISTS trg_custody_audit ON chain_of_custody;
CREATE TRIGGER trg_custody_audit
AFTER INSERT OR UPDATE OR DELETE ON chain_of_custody
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();

DROP TRIGGER IF EXISTS trg_integrity_audit ON integrity_checks;
CREATE TRIGGER trg_integrity_audit
AFTER INSERT OR UPDATE OR DELETE ON integrity_checks
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();

DROP TRIGGER IF EXISTS trg_case_notes_audit ON case_notes;
CREATE TRIGGER trg_case_notes_audit
AFTER INSERT OR UPDATE OR DELETE ON case_notes
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();

DROP TRIGGER IF EXISTS trg_dispositions_audit ON evidence_dispositions;
CREATE TRIGGER trg_dispositions_audit
AFTER INSERT OR UPDATE OR DELETE ON evidence_dispositions
FOR EACH ROW EXECUTE FUNCTION trg_audit_trail();
