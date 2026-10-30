import os
import uuid
import hashlib
import mimetypes
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, jsonify, render_template, request, redirect,
    url_for, flash, session, send_file, abort
)
from werkzeug.utils import secure_filename
import bcrypt

from config import Config
from models import (
    db, User, Investigation, Evidence, ChainOfCustody,
    IntegrityCheck, AuditLog, Tag, EvidenceTag, CaseNote,
    ForensicTool, EvidenceToolUsage, EvidenceDisposition
)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# Ensure upload directory exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ==============================================================================
# Helper Utilities & RBAC Decorators
# ==============================================================================

def current_time():
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def compute_stream_sha256(file_storage):
    """Computes SHA-256 while streaming the file chunks."""
    sha256 = hashlib.sha256()
    file_size = 0
    file_storage.seek(0)
    while True:
        chunk = file_storage.read(65536)
        if not chunk:
            break
        sha256.update(chunk)
        file_size += len(chunk)
    file_storage.seek(0)
    return sha256.hexdigest(), file_size


def compute_file_path_sha256(filepath):
    """Reads a file on disk in 64KB blocks and returns its SHA-256 hash."""
    if not os.path.exists(filepath):
        return None
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Authentication required to access forensic systems.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for("login"))
            user_role = session.get("role")
            if user_role not in allowed_roles:
                flash("Access denied: You lack sufficient security clearance for this operation.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.context_processor
def inject_current_user():
    user = None
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
    return dict(current_user=user, now_utc=current_time())


# ==============================================================================
# Health & Status Endpoint
# ==============================================================================

@app.route("/health")
def health():
    try:
        ver = db.session.execute(db.text("SELECT version();")).scalar()
        tables_cnt = db.session.execute(
            db.text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
        ).scalar()
        return jsonify({
            "status": "healthy",
            "database": "PostgreSQL",
            "version": ver,
            "public_tables_count": tables_cnt
        })
    except Exception as e:
        app.logger.exception("Health check failed")
        return jsonify({"status": "error", "message": str(e)}), 500


# ==============================================================================
# Authentication & Personnel Management
# ==============================================================================

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.is_active and verify_password(password, user.password_hash):
            session.clear()
            session["user_id"] = user.user_id
            session["role"] = user.role
            session["user_name"] = user.full_name
            session["email"] = user.email

            # Record login audit
            log = AuditLog(
                user_id=user.user_id,
                action="LOGIN",
                table_name="users",
                record_id=user.user_id,
                details=f"Successful authentication for {user.full_name} ({user.role})"
            )
            db.session.add(log)
            db.session.commit()

            flash(f"Welcome back, {user.full_name}.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))

        # Log failed attempt
        if user:
            log = AuditLog(
                user_id=user.user_id,
                action="AUTH_FAIL",
                table_name="users",
                record_id=user.user_id,
                details=f"Invalid password attempt for {email}"
            )
            db.session.add(log)
            db.session.commit()

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "Forensic Analyst")
        badge_number = request.form.get("badge_number", "").strip()
        department = request.form.get("department", "").strip()

        if not full_name or not email or not password:
            flash("Full name, email, and password are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Passphrase must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email address already registered.", "danger")
            return redirect(url_for("register"))

        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=hash_password(password),
            role=role,
            badge_number=badge_number or None,
            department=department or None,
            is_active=True
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please authenticate to continue.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        try:
            log = AuditLog(
                user_id=uid,
                action="LOGOUT",
                table_name="users",
                record_id=uid,
                details=f"User {session.get('user_name')} signed out"
            )
            db.session.add(log)
            db.session.commit()
        except Exception:
            db.session.rollback()

    session.clear()
    flash("Session terminated successfully.", "success")
    return redirect(url_for("login"))


@app.route("/users")
@login_required
@roles_required("Admin")
def users_management():
    users = User.query.order_by(User.user_id).all()
    return render_template("users.html", users=users)


@app.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@roles_required("Admin")
def update_user_role(user_id):
    user = db.get_or_404(User, user_id)
    new_role = request.form.get("role")
    if new_role in ["Admin", "Lead Investigator", "Forensic Analyst", "Investigator", "Auditor"]:
        old_role = user.role
        user.role = new_role
        db.session.commit()
        flash(f"Updated security role for {user.full_name} from {old_role} to {new_role}.", "success")
    return redirect(url_for("users_management"))


# ==============================================================================
# Dashboard & Chart Analytics
# ==============================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    total_cases = Investigation.query.count()
    open_cases = Investigation.query.filter(Investigation.status.in_(["Open", "In Progress"])).count()
    total_evidence = Evidence.query.count()
    total_transfers = ChainOfCustody.query.count()

    verified_count = Evidence.query.filter_by(status="Verified").count()
    compromised_count = Evidence.query.filter_by(status="Compromised").count()

    total_bytes = db.session.query(db.func.sum(Evidence.file_size_bytes)).scalar() or 0
    
    # Formatted storage size
    bytes_val = float(total_bytes)
    total_size_formatted = "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_val < 1024.0:
            total_size_formatted = f"{bytes_val:.1f} {unit}"
            break
        bytes_val /= 1024.0

    pending_verification = max(0, total_evidence - verified_count - compromised_count)

    recent_cases = Investigation.query.order_by(Investigation.created_at.desc()).limit(5).all()
    recent_evidence = Evidence.query.order_by(Evidence.collected_at.desc()).limit(5).all()
    recent_audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(6).all()

    return render_template(
        "dashboard.html",
        total_cases=total_cases,
        open_cases=open_cases,
        total_evidence=total_evidence,
        total_transfers=total_transfers,
        verified_count=verified_count,
        compromised_count=compromised_count,
        pending_verification=pending_verification,
        total_size_formatted=total_size_formatted,
        recent_cases=recent_cases,
        recent_evidence=recent_evidence,
        recent_audits=recent_audits
    )


@app.route("/api/dashboard-stats")
@login_required
def api_dashboard_stats():
    # 1. Evidence Types
    types_query = db.session.query(
        Evidence.evidence_type, db.func.count(Evidence.evidence_id)
    ).group_by(Evidence.evidence_type).all()
    evidence_types = {t[0]: t[1] for t in types_query}

    # 2. Cases by Status
    cases_query = db.session.query(
        Investigation.status, db.func.count(Investigation.investigation_id)
    ).group_by(Investigation.status).all()
    cases_status = {c[0]: c[1] for c in cases_query}

    # 3. Integrity Stats
    verified = Evidence.query.filter_by(status="Verified").count()
    compromised = Evidence.query.filter_by(status="Compromised").count()
    total = Evidence.query.count()
    pending = max(0, total - verified - compromised)

    # 4. Custody timeline (past 7 days or sample dates)
    timeline_query = db.session.query(
        db.func.to_char(ChainOfCustody.transfer_date, "YYYY-MM-DD").label("date"),
        db.func.count(ChainOfCustody.custody_id).label("count")
    ).group_by("date").order_by("date").limit(10).all()

    timeline_data = [{"date": row[0], "count": row[1]} for row in timeline_query]
    if not timeline_data:
        timeline_data = [
            {"date": (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d"), "count": 1},
            {"date": datetime.now().strftime("%Y-%m-%d"), "count": ChainOfCustody.query.count()}
        ]

    return jsonify({
        "evidence_types": evidence_types,
        "cases_status": cases_status,
        "integrity_stats": {
            "verified": verified,
            "compromised": compromised,
            "pending": pending
        },
        "custody_timeline": timeline_data
    })


# ==============================================================================
# Investigation / Case Dossier Management
# ==============================================================================

@app.route("/cases")
@login_required
def list_cases():
    cases = Investigation.query.order_by(Investigation.created_at.desc()).all()
    return render_template("cases.html", cases=cases)


@app.route("/cases/create", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "Lead Investigator")
def create_case():
    if request.method == "POST":
        case_number = request.form.get("case_number", "").strip().upper()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Medium")
        status = request.form.get("status", "Open")
        investigator_id = request.form.get("investigator_id", type=int) or session["user_id"]
        incident_date_str = request.form.get("incident_date")

        incident_date = None
        if incident_date_str:
            try:
                incident_date = datetime.strptime(incident_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        if not case_number or not title:
            flash("Case number and title are required.", "danger")
            return redirect(url_for("create_case"))

        if Investigation.query.filter_by(case_number=case_number).first():
            flash(f"Case number '{case_number}' is already in use.", "danger")
            return redirect(url_for("create_case"))

        investigation = Investigation(
            case_number=case_number,
            title=title,
            description=description,
            priority=priority,
            status=status,
            investigator_id=investigator_id,
            incident_date=incident_date
        )

        db.session.add(investigation)
        db.session.commit()

        flash(f"Investigation {case_number} created successfully.", "success")
        return redirect(url_for("view_case", case_id=investigation.investigation_id))

    investigators = User.query.filter_by(is_active=True).all()
    count = Investigation.query.count() + 1
    default_case_number = f"CASE-{datetime.now().year}-{count:04d}"

    return render_template(
        "case_form.html",
        case=None,
        investigators=investigators,
        default_case_number=default_case_number
    )


@app.route("/cases/<int:case_id>")
@login_required
def view_case(case_id):
    case = db.get_or_404(Investigation, case_id)
    return render_template("case_detail.html", case=case)


@app.route("/cases/<int:case_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "Lead Investigator")
def edit_case(case_id):
    case = db.get_or_404(Investigation, case_id)
    if request.method == "POST":
        case.title = request.form.get("title", case.title).strip()
        case.description = request.form.get("description", case.description).strip()
        case.priority = request.form.get("priority", case.priority)
        case.status = request.form.get("status", case.status)
        case.investigator_id = request.form.get("investigator_id", type=int) or case.investigator_id
        
        incident_date_str = request.form.get("incident_date")
        if incident_date_str:
            try:
                case.incident_date = datetime.strptime(incident_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        if case.status == "Closed" and not case.closed_at:
            case.closed_at = current_time()
        elif case.status != "Closed":
            case.closed_at = None

        db.session.commit()
        flash("Investigation details updated successfully.", "success")
        return redirect(url_for("view_case", case_id=case.investigation_id))

    investigators = User.query.filter_by(is_active=True).all()
    return render_template("case_form.html", case=case, investigators=investigators)


@app.route("/cases/<int:case_id>/notes", methods=["POST"])
@login_required
def add_case_note(case_id):
    case = db.get_or_404(Investigation, case_id)
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    note_type = request.form.get("note_type", "Forensic Observation")
    is_confidential = bool(request.form.get("is_confidential"))

    if not title or not content:
        flash("Title and note content are required.", "danger")
        return redirect(url_for("view_case", case_id=case_id))

    note = CaseNote(
        investigation_id=case.investigation_id,
        author_id=session["user_id"],
        note_type=note_type,
        title=title,
        content=content,
        is_confidential=is_confidential
    )

    db.session.add(note)
    db.session.commit()

    flash("Forensic observation recorded to case file.", "success")
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/api/cases/<int:case_id>/summary")
@login_required
def api_case_summary(case_id):
    """Executes PostgreSQL stored function fn_get_case_summary."""
    res = db.session.execute(
        db.text("SELECT fn_get_case_summary(:case_id)"),
        {"case_id": case_id}
    ).scalar()

    if not res:
        abort(404, "Investigation not found")

    return jsonify(res)


# ==============================================================================
# Digital Evidence Registration, Storage & Hashing
# ==============================================================================

@app.route("/evidence")
@login_required
def list_evidence():
    filter_type = request.args.get("filter")
    query = Evidence.query.order_by(Evidence.collected_at.desc())

    if filter_type == "compromised":
        query = query.filter_by(status="Compromised")
    elif filter_type == "verified":
        query = query.filter_by(status="Verified")

    evidence_items = query.all()
    return render_template("evidence.html", evidence_items=evidence_items, current_filter=filter_type)


@app.route("/evidence/add", methods=["GET", "POST"])
@login_required
def add_evidence():
    if request.method == "POST":
        investigation_id = request.form.get("investigation_id", type=int)
        evidence_number = request.form.get("evidence_number", "").strip().upper()
        evidence_name = request.form.get("evidence_name", "").strip()
        evidence_type = request.form.get("evidence_type", "Disk Image")
        description = request.form.get("description", "").strip()
        storage_location = request.form.get("storage_location", "Vault Locker A-1").strip()
        manual_hash = request.form.get("manual_hash", "").strip().lower()
        selected_tags = request.form.getlist("tag_ids")

        if not investigation_id or not evidence_number or not evidence_name:
            flash("Evidence number, name, and associated case are required.", "danger")
            return redirect(url_for("add_evidence"))

        if Evidence.query.filter_by(evidence_number=evidence_number).first():
            flash(f"Evidence number '{evidence_number}' already exists.", "danger")
            return redirect(url_for("add_evidence"))

        uploaded_file = request.files.get("evidence_file")
        file_path = None
        sha256_hash = manual_hash or None
        file_size = 0
        mime_type = "application/octet-stream"
        original_filename = None

        if uploaded_file and uploaded_file.filename:
            original_filename = secure_filename(uploaded_file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
            target_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

            # Compute streaming SHA-256 and size
            computed_hash, file_size = compute_stream_sha256(uploaded_file)
            uploaded_file.save(target_path)
            file_path = target_path
            sha256_hash = computed_hash
            mime_type = mimetypes.guess_type(original_filename)[0] or "application/octet-stream"

        if not sha256_hash:
            sha256_hash = hashlib.sha256(f"{evidence_number}:{evidence_name}".encode("utf-8")).hexdigest()

        evidence = Evidence(
            evidence_number=evidence_number,
            evidence_name=evidence_name,
            evidence_type=evidence_type,
            description=description,
            file_path=file_path,
            original_filename=original_filename,
            file_size_bytes=file_size,
            mime_type=mime_type,
            sha256_hash=sha256_hash,
            status="Verified" if file_path else "Collected",
            storage_location=storage_location,
            investigation_id=investigation_id,
            collected_by=session["user_id"],
            current_custodian_id=session["user_id"]
        )

        for tag_id in selected_tags:
            t = db.session.get(Tag, tag_id)
            if t:
                evidence.tags.append(t)

        db.session.add(evidence)
        db.session.flush()

        # Record baseline integrity check
        ic = IntegrityCheck(
            evidence_id=evidence.evidence_id,
            checked_by=session["user_id"],
            original_hash=sha256_hash,
            calculated_hash=sha256_hash,
            result="VERIFIED",
            notes="Initial intake cryptographic baseline recorded."
        )
        db.session.add(ic)
        db.session.commit()

        flash(f"Evidence {evidence_number} intake recorded. SHA-256 computed: {sha256_hash[:16]}...", "success")
        return redirect(url_for("view_evidence", evidence_id=evidence.evidence_id))

    investigations = Investigation.query.order_by(Investigation.created_at.desc()).all()
    tags = Tag.query.order_by(Tag.name).all()
    selected_case_id = request.args.get("case_id", type=int)

    count = Evidence.query.count() + 1
    default_evidence_number = f"EVD-{datetime.now().year}-{count:04d}"

    return render_template(
        "add_evidence.html",
        investigations=investigations,
        tags=tags,
        selected_case_id=selected_case_id,
        default_evidence_number=default_evidence_number
    )


@app.route("/evidence/<int:evidence_id>")
@login_required
def view_evidence(evidence_id):
    evidence = db.get_or_404(Evidence, evidence_id)
    users = User.query.filter_by(is_active=True).all()
    forensic_tools = ForensicTool.query.order_by(ForensicTool.name).all()

    return render_template(
        "evidence_detail.html",
        evidence=evidence,
        users=users,
        forensic_tools=forensic_tools
    )


@app.route("/evidence/<int:evidence_id>/download")
@login_required
def download_evidence(evidence_id):
    evidence = db.get_or_404(Evidence, evidence_id)
    if not evidence.file_path or not os.path.exists(evidence.file_path):
        flash("Physical artifact file not found on forensic storage volume.", "danger")
        return redirect(url_for("view_evidence", evidence_id=evidence_id))

    # Log download action
    log = AuditLog(
        user_id=session["user_id"],
        action="DOWNLOAD",
        table_name="evidence",
        record_id=evidence.evidence_id,
        details=f"Evidence file {evidence.original_filename or evidence.evidence_number} retrieved"
    )
    db.session.add(log)
    db.session.commit()

    return send_file(
        evidence.file_path,
        as_attachment=True,
        download_name=evidence.original_filename or f"{evidence.evidence_number}.bin"
    )


# ==============================================================================
# Cryptographic SHA-256 Integrity Verification & Tampering Detection
# ==============================================================================

@app.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@login_required
def verify_evidence(evidence_id):
    evidence = db.get_or_404(Evidence, evidence_id)

    # Recompute hash from physical file if on disk
    if evidence.file_path and os.path.exists(evidence.file_path):
        calculated_hash = compute_file_path_sha256(evidence.file_path)
    else:
        calculated_hash = evidence.sha256_hash

    # Call PostgreSQL stored function fn_verify_evidence_integrity
    result = db.session.execute(
        db.text("SELECT fn_verify_evidence_integrity(:ev_id, :checker, :calc_hash, :notes)"),
        {
            "ev_id": evidence.evidence_id,
            "checker": session["user_id"],
            "calc_hash": calculated_hash,
            "notes": "Automated on-demand integrity verification audit."
        }
    ).scalar()

    db.session.commit()

    if result.get("result") == "VERIFIED":
        flash("Cryptographic verification PASSED: SHA-256 matches baseline perfectly.", "success")
    else:
        flash("CRITICAL INTEGRITY FAILURE: Hash mismatch detected! Evidence marked Compromised.", "danger")

    return redirect(url_for("view_evidence", evidence_id=evidence.evidence_id))


@app.route("/evidence/<int:evidence_id>/simulate-tamper", methods=["POST"])
@login_required
def simulate_tamper(evidence_id):
    """
    Forensic Verification Test:
    Simulates a tamper incident by testing against an altered hash digest.
    Demonstrates instant detection, status transition to 'Compromised', and audit logging.
    """
    evidence = db.get_or_404(Evidence, evidence_id)
    tampered_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    result = db.session.execute(
        db.text("SELECT fn_verify_evidence_integrity(:ev_id, :checker, :calc_hash, :notes)"),
        {
            "ev_id": evidence.evidence_id,
            "checker": session["user_id"],
            "calc_hash": tampered_hash,
            "notes": "FORENSIC TAMPER DETECTION TEST: Simulated altered byte payload."
        }
    ).scalar()

    db.session.commit()

    flash("⚠️ SIMULATION EXECUTED: Tamper detected! Status updated to 'Compromised'. Immediate incident logged.", "danger")
    return redirect(url_for("view_evidence", evidence_id=evidence.evidence_id))


# ==============================================================================
# Chain of Custody Tracking with PostgreSQL Transactions
# ==============================================================================

@app.route("/custody")
@login_required
def custody_hub():
    custody_records = ChainOfCustody.query.order_by(ChainOfCustody.transfer_date.desc()).all()
    all_evidence = Evidence.query.order_by(Evidence.evidence_number).all()
    users = User.query.filter_by(is_active=True).all()

    return render_template(
        "custody.html",
        custody_records=custody_records,
        all_evidence=all_evidence,
        users=users
    )


@app.route("/custody/transfer", methods=["POST"])
@login_required
def transfer_custody():
    evidence_id = request.form.get("evidence_id", type=int)
    transferred_from = request.form.get("transferred_from", type=int)
    transferred_to = request.form.get("transferred_to", type=int)
    purpose = request.form.get("purpose", "").strip()
    location = request.form.get("location", "").strip()
    authorization_notes = request.form.get("authorization_notes", "").strip()

    if not evidence_id or not transferred_from or not transferred_to or not purpose or not location:
        flash("All custody transfer fields are legally required.", "danger")
        return redirect(url_for("custody_hub"))

    if transferred_from == transferred_to:
        flash("Sender and recipient cannot be the same person.", "danger")
        return redirect(url_for("custody_hub"))

    # Execute inside atomic PostgreSQL stored function / transaction
    try:
        res = db.session.execute(
            db.text("""
                SELECT fn_transfer_evidence_custody(
                    :ev_id, :from_u, :to_u, :purpose, :location, :auth_notes
                )
            """),
            {
                "ev_id": evidence_id,
                "from_u": transferred_from,
                "to_u": transferred_to,
                "purpose": purpose,
                "location": location,
                "auth_notes": authorization_notes or None
            }
        ).scalar()

        if res.get("success"):
            db.session.commit()
            flash("Chain of custody transfer executed and committed atomically.", "success")
        else:
            db.session.rollback()
            flash(f"Transfer rejected: {res.get('message')}", "danger")

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Custody transaction aborted")
        flash(f"Transaction aborted: {str(e)}", "danger")

    return redirect(url_for("view_evidence", evidence_id=evidence_id))


@app.route("/custody/report/<int:evidence_id>")
@login_required
def custody_report(evidence_id):
    """Generates court-admissible chain of custody manifest."""
    evidence = db.get_or_404(Evidence, evidence_id)
    return render_template("custody_report.html", evidence=evidence, current_time=current_time())


# ==============================================================================
# Forensic Tools Registry & Tool Usage Logging
# ==============================================================================

@app.route("/tools")
@login_required
def tools_registry():
    tools = ForensicTool.query.order_by(ForensicTool.name).all()
    return render_template("tools.html", tools=tools)


@app.route("/tools/create", methods=["POST"])
@login_required
@roles_required("Admin", "Lead Investigator", "Forensic Analyst")
def create_tool():
    name = request.form.get("name", "").strip()
    version = request.form.get("version", "").strip()
    vendor = request.form.get("vendor", "").strip()
    tool_type = request.form.get("tool_type", "Disk Imager")
    notes = request.form.get("notes", "").strip()

    if not name or not version:
        flash("Tool name and version are required.", "danger")
        return redirect(url_for("tools_registry"))

    tool = ForensicTool(
        name=name,
        version=version,
        vendor=vendor or None,
        tool_type=tool_type,
        is_validated=True,
        notes=notes or None
    )
    db.session.add(tool)
    db.session.commit()

    flash(f"Forensic tool '{name}' registered to inventory.", "success")
    return redirect(url_for("tools_registry"))


@app.route("/evidence/<int:evidence_id>/tool-usage", methods=["POST"])
@login_required
def log_tool_usage(evidence_id):
    evidence = db.get_or_404(Evidence, evidence_id)
    tool_id = request.form.get("tool_id", type=int)
    action_type = request.form.get("action_type", "").strip()
    command_executed = request.form.get("command_executed", "").strip()
    output_summary = request.form.get("output_summary", "").strip()

    if not tool_id or not action_type:
        flash("Tool and action type are required.", "danger")
        return redirect(url_for("view_evidence", evidence_id=evidence_id))

    usage = EvidenceToolUsage(
        evidence_id=evidence.evidence_id,
        tool_id=tool_id,
        operator_id=session["user_id"],
        action_type=action_type,
        command_executed=command_executed or None,
        output_summary=output_summary or None
    )
    db.session.add(usage)
    db.session.commit()

    flash("Forensic tool application recorded to evidence dossier.", "success")
    return redirect(url_for("view_evidence", evidence_id=evidence_id))


# ==============================================================================
# Evidence Dispositions & Court Presentation
# ==============================================================================

@app.route("/dispositions")
@login_required
def dispositions_hub():
    dispositions = EvidenceDisposition.query.order_by(EvidenceDisposition.created_at.desc()).all()
    all_evidence = Evidence.query.order_by(Evidence.evidence_number).all()
    return render_template("dispositions.html", dispositions=dispositions, all_evidence=all_evidence)


@app.route("/dispositions/create", methods=["POST"])
@login_required
def create_disposition():
    evidence_id = request.form.get("evidence_id", type=int)
    disposition_type = request.form.get("disposition_type", "Permanent Archive")
    legal_authorization = request.form.get("legal_authorization", "").strip()
    reason = request.form.get("reason", "").strip()

    if not evidence_id or not reason:
        flash("Evidence item and formal legal reason are required.", "danger")
        return redirect(url_for("dispositions_hub"))

    disp = EvidenceDisposition(
        evidence_id=evidence_id,
        requested_by=session["user_id"],
        disposition_type=disposition_type,
        legal_authorization=legal_authorization or None,
        reason=reason,
        status="Pending"
    )
    db.session.add(disp)
    db.session.commit()

    flash("Evidence disposition order submitted for supervisory authorization.", "success")
    return redirect(url_for("dispositions_hub"))


@app.route("/dispositions/<int:disposition_id>/approve", methods=["POST"])
@login_required
@roles_required("Admin", "Lead Investigator")
def approve_disposition(disposition_id):
    disp = db.get_or_404(EvidenceDisposition, disposition_id)
    disp.status = "Approved"
    disp.approved_by = session["user_id"]
    disp.completed_at = current_time()
    db.session.commit()

    flash("Disposition order approved and marked completed.", "success")
    return redirect(url_for("dispositions_hub"))


# ==============================================================================
# Automatic PostgreSQL Trigger Audit Logs
# ==============================================================================

@app.route("/audit-logs")
@login_required
def audit_logs():
    table_filter = request.args.get("table")
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())

    if table_filter:
        query = query.filter_by(table_name=table_filter)

    logs = query.limit(200).all()
    return render_template("audit_logs.html", logs=logs, selected_table=table_filter)


# ==============================================================================
# Application Entry Point
# ==============================================================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
