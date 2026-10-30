from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()


def current_time():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="Investigator")
    badge_number = db.Column(db.String(50))
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)

    # Relationships
    investigations = db.relationship("Investigation", back_populates="investigator", lazy="dynamic")
    collected_evidence = db.relationship("Evidence", foreign_keys="Evidence.collected_by", back_populates="collector", lazy="dynamic")
    custodian_evidence = db.relationship("Evidence", foreign_keys="Evidence.current_custodian_id", back_populates="current_custodian", lazy="dynamic")
    sent_transfers = db.relationship("ChainOfCustody", foreign_keys="ChainOfCustody.transferred_from", back_populates="sender", lazy="dynamic")
    received_transfers = db.relationship("ChainOfCustody", foreign_keys="ChainOfCustody.transferred_to", back_populates="receiver", lazy="dynamic")
    case_notes = db.relationship("CaseNote", back_populates="author", lazy="dynamic")
    tool_usages = db.relationship("EvidenceToolUsage", back_populates="operator", lazy="dynamic")

    @property
    def is_admin(self):
        return self.role == "Admin"

    @property
    def is_lead(self):
        return self.role in ["Admin", "Lead Investigator"]

    @property
    def can_modify_evidence(self):
        return self.role in ["Admin", "Lead Investigator", "Forensic Analyst", "Investigator"]

    @property
    def is_auditor(self):
        return self.role == "Auditor"

    def has_role(self, *roles):
        return self.role in roles


class Investigation(db.Model):
    __tablename__ = "investigations"

    investigation_id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(30), default="Open")  # Open, In Progress, Pending Review, Closed, Archived
    priority = db.Column(db.String(20), default="Medium")  # Low, Medium, High, Critical
    incident_date = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)
    closed_at = db.Column(db.DateTime(timezone=True))

    investigator_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    # Relationships
    investigator = db.relationship("User", back_populates="investigations")
    evidence_items = db.relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan", lazy="dynamic")
    notes = db.relationship("CaseNote", back_populates="investigation", cascade="all, delete-orphan", lazy="dynamic", order_by="desc(CaseNote.created_at)")


class Evidence(db.Model):
    __tablename__ = "evidence"

    evidence_id = db.Column(db.Integer, primary_key=True)
    evidence_number = db.Column(db.String(50), unique=True, nullable=False)
    evidence_name = db.Column(db.String(200), nullable=False)
    evidence_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(500))
    original_filename = db.Column(db.String(255))
    file_size_bytes = db.Column(db.BigInteger, default=0)
    mime_type = db.Column(db.String(100))
    sha256_hash = db.Column(db.String(64))
    collected_at = db.Column(db.DateTime(timezone=True), default=current_time)
    status = db.Column(db.String(30), default="Collected")  # Collected, In Analysis, In Custody, Verified, Compromised, Transferred, Archived, Disposed
    storage_location = db.Column(db.String(200), default="Evidence Locker A-1")

    investigation_id = db.Column(
        db.Integer,
        db.ForeignKey("investigations.investigation_id"),
        nullable=False
    )

    collected_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    current_custodian_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id")
    )

    # Relationships
    investigation = db.relationship("Investigation", back_populates="evidence_items")
    collector = db.relationship("User", foreign_keys=[collected_by], back_populates="collected_evidence")
    current_custodian = db.relationship("User", foreign_keys=[current_custodian_id], back_populates="custodian_evidence")
    custody_records = db.relationship("ChainOfCustody", back_populates="evidence", cascade="all, delete-orphan", lazy="dynamic", order_by="desc(ChainOfCustody.transfer_date)")
    integrity_checks = db.relationship("IntegrityCheck", back_populates="evidence", cascade="all, delete-orphan", lazy="dynamic", order_by="desc(IntegrityCheck.checked_at)")
    tags = db.relationship("Tag", secondary="evidence_tags", back_populates="evidence_items")
    tool_usages = db.relationship("EvidenceToolUsage", back_populates="evidence", lazy="dynamic", order_by="desc(EvidenceToolUsage.used_at)")
    dispositions = db.relationship("EvidenceDisposition", back_populates="evidence", lazy="dynamic", order_by="desc(EvidenceDisposition.created_at)")

    @property
    def designated_custodian(self):
        return self.current_custodian if self.current_custodian else self.collector

    @property
    def formatted_size(self):
        if not self.file_size_bytes:
            return "0 B"
        bytes_val = float(self.file_size_bytes)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} PB"


class ChainOfCustody(db.Model):
    __tablename__ = "chain_of_custody"

    custody_id = db.Column(db.Integer, primary_key=True)

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.evidence_id"),
        nullable=False
    )

    transferred_from = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    transferred_to = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    transfer_date = db.Column(db.DateTime(timezone=True), default=current_time)
    purpose = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200))
    authorization_notes = db.Column(db.Text)

    evidence = db.relationship("Evidence", back_populates="custody_records")
    sender = db.relationship("User", foreign_keys=[transferred_from], back_populates="sent_transfers")
    receiver = db.relationship("User", foreign_keys=[transferred_to], back_populates="received_transfers")


class IntegrityCheck(db.Model):
    __tablename__ = "integrity_checks"

    check_id = db.Column(db.Integer, primary_key=True)

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.evidence_id"),
        nullable=False
    )

    checked_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    original_hash = db.Column(db.String(64), nullable=False)
    calculated_hash = db.Column(db.String(64), nullable=False)
    result = db.Column(db.String(20), nullable=False)  # VERIFIED, TAMPERED
    notes = db.Column(db.Text)
    checked_at = db.Column(db.DateTime(timezone=True), default=current_time)

    evidence = db.relationship("Evidence", back_populates="integrity_checks")
    checker = db.relationship("User")

    @property
    def is_verified(self):
        return self.result == "VERIFIED"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    log_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id")
    )

    action = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(100))
    record_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime(timezone=True), default=current_time)

    user = db.relationship("User")


class Tag(db.Model):
    __tablename__ = "tags"

    tag_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    color_code = db.Column(db.String(20), default="#38bdf8")
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)

    evidence_items = db.relationship("Evidence", secondary="evidence_tags", back_populates="tags")


class EvidenceTag(db.Model):
    __tablename__ = "evidence_tags"

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.evidence_id", ondelete="CASCADE"),
        primary_key=True
    )
    tag_id = db.Column(
        db.Integer,
        db.ForeignKey("tags.tag_id", ondelete="CASCADE"),
        primary_key=True
    )
    tagged_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id")
    )
    tagged_at = db.Column(db.DateTime(timezone=True), default=current_time)

    tagger = db.relationship("User")


class CaseNote(db.Model):
    __tablename__ = "case_notes"

    note_id = db.Column(db.Integer, primary_key=True)

    investigation_id = db.Column(
        db.Integer,
        db.ForeignKey("investigations.investigation_id", ondelete="CASCADE"),
        nullable=False
    )

    author_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    note_type = db.Column(db.String(50), nullable=False, default="Forensic Observation")
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_confidential = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)
    updated_at = db.Column(db.DateTime(timezone=True), default=current_time, onupdate=current_time)

    investigation = db.relationship("Investigation", back_populates="notes")
    author = db.relationship("User", back_populates="case_notes")


class ForensicTool(db.Model):
    __tablename__ = "forensic_tools"

    tool_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    vendor = db.Column(db.String(150))
    tool_type = db.Column(db.String(50), nullable=False)  # Disk Imager, Memory Analyzer, Network Analyzer, etc.
    is_validated = db.Column(db.Boolean, default=True)
    validation_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)

    usages = db.relationship("EvidenceToolUsage", back_populates="tool", lazy="dynamic")


class EvidenceToolUsage(db.Model):
    __tablename__ = "evidence_tool_usage"

    usage_id = db.Column(db.Integer, primary_key=True)

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.evidence_id", ondelete="RESTRICT"),
        nullable=False
    )

    tool_id = db.Column(
        db.Integer,
        db.ForeignKey("forensic_tools.tool_id", ondelete="RESTRICT"),
        nullable=False
    )

    operator_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    action_type = db.Column(db.String(100), nullable=False)
    command_executed = db.Column(db.Text)
    output_summary = db.Column(db.Text)
    used_at = db.Column(db.DateTime(timezone=True), default=current_time)

    evidence = db.relationship("Evidence", back_populates="tool_usages")
    tool = db.relationship("ForensicTool", back_populates="usages")
    operator = db.relationship("User", back_populates="tool_usages")


class EvidenceDisposition(db.Model):
    __tablename__ = "evidence_dispositions"

    disposition_id = db.Column(db.Integer, primary_key=True)

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.evidence_id", ondelete="RESTRICT"),
        nullable=False
    )

    requested_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    approved_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id")
    )

    disposition_type = db.Column(db.String(50), nullable=False)  # Return to Owner, Cryptographic Shredding, Permanent Archive, Court Presentation
    status = db.Column(db.String(30), default="Pending")  # Pending, Approved, Rejected, Completed
    reason = db.Column(db.Text, nullable=False)
    legal_authorization = db.Column(db.String(200))
    completed_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=current_time)

    evidence = db.relationship("Evidence", back_populates="dispositions")
    requester = db.relationship("User", foreign_keys=[requested_by])
    approver = db.relationship("User", foreign_keys=[approved_by])
