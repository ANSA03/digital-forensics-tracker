import io
import os
import unittest
import hashlib
from datetime import datetime, timezone

from app import app
from models import (
    db, User, Investigation, Evidence, ChainOfCustody,
    IntegrityCheck, AuditLog, Tag, CaseNote, ForensicTool,
    EvidenceToolUsage, EvidenceDisposition
)


class ForensicsTrackerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def login_as(self, email, password):
        return self.client.post("/login", data={
            "email": email,
            "password": password
        }, follow_redirects=True)

    def logout(self):
        return self.client.get("/logout", follow_redirects=True)

    # 1. Health & Database Test
    def test_01_health_check(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "PostgreSQL")
        self.assertGreaterEqual(data["public_tables_count"], 12)

    # 2. Authentication & RBAC Tests
    def test_02_authentication_and_rbac(self):
        # Test valid login
        res = self.login_as("admin@forensics.local", "AdminSecure123!")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Welcome back", res.data)

        # Test admin access to /users
        res_users = self.client.get("/users")
        self.assertEqual(res_users.status_code, 200)
        self.assertIn(b"Registered Forensic Personnel", res_users.data)
        self.logout()

        # Test investigator login and access control (cannot view /users)
        res_lead = self.login_as("alex.cross@forensics.local", "Investigator123!")
        self.assertEqual(res_lead.status_code, 200)
        res_denied = self.client.get("/users", follow_redirects=True)
        self.assertIn(b"Access denied", res_denied.data)
        self.logout()

        # Test unauthenticated access redirects to login
        res_unauth = self.client.get("/dashboard")
        self.assertEqual(res_unauth.status_code, 302)
        self.assertIn("/login", res_unauth.headers["Location"])

    # 3. Investigation Creation & Search
    def test_03_investigation_management(self):
        self.login_as("alex.cross@forensics.local", "Investigator123!")
        test_case_num = f"CASE-TEST-{datetime.now().strftime('%H%M%S')}"

        # Create investigation
        res_create = self.client.post("/cases/create", data={
            "case_number": test_case_num,
            "title": "Automated Unit Test Infiltration Inquiry",
            "priority": "High",
            "status": "In Progress",
            "description": "Synthetic testing dossier for automated regression validation."
        }, follow_redirects=True)

        self.assertEqual(res_create.status_code, 200)
        self.assertIn(test_case_num.encode(), res_create.data)

        # Retrieve investigation from database
        case = Investigation.query.filter_by(case_number=test_case_num).first()
        self.assertIsNotNone(case)
        self.assertEqual(case.priority, "High")

        # Test API summary stored function
        res_api = self.client.get(f"/api/cases/{case.investigation_id}/summary")
        self.assertEqual(res_api.status_code, 200)
        summary = res_api.get_json()
        self.assertEqual(summary["case_number"], test_case_num)

        # Test adding forensic case note
        res_note = self.client.post(f"/cases/{case.investigation_id}/notes", data={
            "title": "Sandbox Test Observation",
            "content": "Observed zero-packet beaconing activity in isolated runtime.",
            "note_type": "Forensic Observation"
        }, follow_redirects=True)
        self.assertEqual(res_note.status_code, 200)
        self.assertIn(b"Sandbox Test Observation", res_note.data)
        self.logout()

    # 4. Digital Evidence Registration & File Upload with SHA-256 Hashing
    def test_04_evidence_registration_and_hashing(self):
        self.login_as("elena.rostova@forensics.local", "Analyst123!")
        case = Investigation.query.first()
        self.assertIsNotNone(case)

        test_evd_num = f"EVD-TEST-{datetime.now().strftime('%H%M%S')}"
        fake_binary_content = b"FORENSIC_RAW_PACKET_DUMP_VALIDATION_STREAM_12345"
        expected_sha256 = hashlib.sha256(fake_binary_content).hexdigest()

        # Post multipart file upload
        data = {
            "evidence_number": test_evd_num,
            "evidence_name": "Test Memory Dump Stream",
            "investigation_id": case.investigation_id,
            "evidence_type": "Memory Dump",
            "storage_location": "Vault Locker B-12",
            "description": "Synthesized memory stream for unit testing verification.",
            "evidence_file": (io.BytesIO(fake_binary_content), "test_stream.bin")
        }

        res = self.client.post("/evidence/add", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(test_evd_num.encode(), res.data)

        # Verify database record and computed SHA-256
        ev = Evidence.query.filter_by(evidence_number=test_evd_num).first()
        self.assertIsNotNone(ev)
        self.assertEqual(ev.sha256_hash, expected_sha256)
        self.assertEqual(ev.file_size_bytes, len(fake_binary_content))
        self.assertEqual(ev.status, "Verified")
        self.assertTrue(os.path.exists(ev.file_path))

        # Test download
        res_dl = self.client.get(f"/evidence/{ev.evidence_id}/download")
        self.assertEqual(res_dl.status_code, 200)
        self.assertEqual(res_dl.data, fake_binary_content)
        res_dl.close()
        self.logout()

    # 5. SHA-256 Integrity Verification and Tampering Detection
    def test_05_integrity_verification_and_tamper_detection(self):
        self.login_as("elena.rostova@forensics.local", "Analyst123!")
        ev = Evidence.query.filter(Evidence.file_path.isnot(None)).first()
        self.assertIsNotNone(ev)

        # 1. Normal verification passes
        res_verify = self.client.post(f"/evidence/{ev.evidence_id}/verify", follow_redirects=True)
        self.assertEqual(res_verify.status_code, 200)
        self.assertIn(b"Cryptographic verification PASSED", res_verify.data)

        # 2. Tamper simulation detects mismatch and updates status to Compromised
        res_tamper = self.client.post(f"/evidence/{ev.evidence_id}/simulate-tamper", follow_redirects=True)
        self.assertEqual(res_tamper.status_code, 200)
        self.assertIn(b"Tamper detected", res_tamper.data)

        # Reload evidence from DB
        db.session.refresh(ev)
        self.assertEqual(ev.status, "Compromised")

        # Verify integrity check record logged in DB
        last_check = IntegrityCheck.query.filter_by(evidence_id=ev.evidence_id).order_by(IntegrityCheck.checked_at.desc()).first()
        self.assertIsNotNone(last_check)
        self.assertEqual(last_check.result, "TAMPERED")

        # Restore evidence to Verified
        ev.status = "Verified"
        db.session.commit()
        self.logout()

    # 6. Chain-of-Custody Tracking with PostgreSQL Transactions
    def test_06_chain_of_custody_transactions(self):
        self.login_as("alex.cross@forensics.local", "Investigator123!")
        ev = Evidence.query.first()
        self.assertIsNotNone(ev)

        sender_id = ev.designated_custodian.user_id
        target_recipient = User.query.filter(User.user_id != sender_id).first()
        self.assertIsNotNone(target_recipient)

        # 1. Successful Custody Transfer
        res_transfer = self.client.post("/custody/transfer", data={
            "evidence_id": ev.evidence_id,
            "transferred_from": sender_id,
            "transferred_to": target_recipient.user_id,
            "purpose": "Unit testing atomic custodial transfer",
            "location": "Forensic Clean Room 101",
            "authorization_notes": "Warrant #UNIT-TEST-001"
        }, follow_redirects=True)

        self.assertEqual(res_transfer.status_code, 200)
        self.assertIn(b"Chain of custody transfer executed and committed atomically", res_transfer.data)

        # Verify evidence custodian updated
        db.session.refresh(ev)
        self.assertEqual(ev.current_custodian_id, target_recipient.user_id)
        self.assertEqual(ev.storage_location, "Forensic Clean Room 101")

        # 2. Unauthorized sender rejection (cannot transfer if not the custodian)
        current_custodian = ev.designated_custodian
        other_users = User.query.filter(User.user_id != current_custodian.user_id).limit(2).all()
        invalid_sender = other_users[0]
        distinct_recipient = other_users[1] if len(other_users) > 1 else current_custodian

        res_reject = self.client.post("/custody/transfer", data={
            "evidence_id": ev.evidence_id,
            "transferred_from": invalid_sender.user_id,
            "transferred_to": distinct_recipient.user_id,
            "purpose": "Unauthorized illicit transfer attempt",
            "location": "Unauthorized Location"
        }, follow_redirects=True)

        self.assertEqual(res_reject.status_code, 200)
        self.assertIn(b"Transfer denied", res_reject.data)

        # 3. Test Court-admissible report endpoint
        res_rep = self.client.get(f"/custody/report/{ev.evidence_id}")
        self.assertEqual(res_rep.status_code, 200)
        self.assertIn(b"Official Chain of Custody Record", res_rep.data)
        self.logout()

    # 7. PostgreSQL Trigger-based Automated Audit Logging
    def test_07_postgresql_trigger_audit_logging(self):
        self.login_as("admin@forensics.local", "AdminSecure123!")
        admin = User.query.filter_by(role="Admin").first()

        # Insert a case note to test trigger
        case = Investigation.query.first()
        note = CaseNote(
            investigation_id=case.investigation_id,
            author_id=admin.user_id,
            title="Trigger Testing Note",
            content="Testing that PostgreSQL triggers automatically log this action."
        )
        db.session.add(note)
        db.session.commit()

        # Verify that trigger trg_audit_trail inserted into audit_logs
        trigger_log = AuditLog.query.filter_by(
            table_name="case_notes",
            record_id=note.note_id,
            action="INSERT"
        ).first()

        self.assertIsNotNone(trigger_log, "PostgreSQL trigger should have recorded case_notes INSERT in audit_logs")
        self.assertIn("Trigger Testing Note", trigger_log.details)

        # Clean up test note
        db.session.delete(note)
        db.session.commit()

        # Verify DELETE was also captured by trigger!
        delete_log = AuditLog.query.filter_by(
            table_name="case_notes",
            record_id=note.note_id,
            action="DELETE"
        ).first()
        self.assertIsNotNone(delete_log, "PostgreSQL trigger should have recorded case_notes DELETE in audit_logs")
        self.logout()

    # 8. Analytical Views & Stored Functions
    def test_08_sql_views_and_functions(self):
        # 1. View v_evidence_custody_overview
        v_evidence = db.session.execute(
            db.text("SELECT * FROM v_evidence_custody_overview LIMIT 5")
        ).fetchall()
        self.assertGreater(len(v_evidence), 0)

        # 2. View v_investigation_metrics
        v_metrics = db.session.execute(
            db.text("SELECT * FROM v_investigation_metrics LIMIT 5")
        ).fetchall()
        self.assertGreater(len(v_metrics), 0)

        # 3. View v_chain_of_custody_timeline
        v_timeline = db.session.execute(
            db.text("SELECT * FROM v_chain_of_custody_timeline LIMIT 5")
        ).fetchall()
        self.assertGreater(len(v_timeline), 0)

        # 4. Stored function fn_get_case_summary
        case = Investigation.query.first()
        res_summary = db.session.execute(
            db.text("SELECT fn_get_case_summary(:cid)"),
            {"cid": case.investigation_id}
        ).scalar()
        self.assertIsNotNone(res_summary)
        self.assertEqual(res_summary["case_number"], case.case_number)
        self.assertIn("total_evidence", res_summary)

    # 9. Dashboard API Stats
    def test_09_dashboard_stats_api(self):
        self.login_as("admin@forensics.local", "AdminSecure123!")
        res = self.client.get("/api/dashboard-stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("evidence_types", data)
        self.assertIn("cases_status", data)
        self.assertIn("integrity_stats", data)
        self.assertIn("custody_timeline", data)
        self.logout()

    # 10. Forensic Tools & Dispositions
    def test_10_tools_and_dispositions(self):
        self.login_as("admin@forensics.local", "AdminSecure123!")
        ev = Evidence.query.first()

        # Create disposition request
        res_disp = self.client.post("/dispositions/create", data={
            "evidence_id": ev.evidence_id,
            "disposition_type": "Permanent Archive",
            "legal_authorization": "Court Order #2026-TEST-99",
            "reason": "Retention testing for forensic archive."
        }, follow_redirects=True)
        self.assertEqual(res_disp.status_code, 200)

        disp = EvidenceDisposition.query.filter_by(evidence_id=ev.evidence_id).order_by(EvidenceDisposition.created_at.desc()).first()
        self.assertIsNotNone(disp)

        # Approve disposition
        res_app = self.client.post(f"/dispositions/{disp.disposition_id}/approve", follow_redirects=True)
        self.assertEqual(res_app.status_code, 200)
        db.session.refresh(disp)
        self.assertEqual(disp.status, "Approved")
        self.assertIsNotNone(disp.completed_at)
        self.logout()


if __name__ == "__main__":
    unittest.main()
