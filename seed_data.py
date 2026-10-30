import os
import hashlib
import bcrypt
from datetime import datetime, timezone, timedelta
from app import app
from models import (
    db, User, Investigation, Evidence, ChainOfCustody, 
    IntegrityCheck, AuditLog, Tag, EvidenceTag, CaseNote, 
    ForensicTool, EvidenceToolUsage, EvidenceDisposition
)

def current_time():
    return datetime.now(timezone.utc)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def seed_database():
    with app.app_context():
        # Check if users already exist
        if User.query.first():
            print("Database already contains users. Skipping full initial seed.")
            return

        print("Seeding database with realistic forensic data...")

        # 1. Users
        users_data = [
            {
                "full_name": "Chief Director Sarah Vance",
                "email": "admin@forensics.local",
                "password_hash": hash_password("AdminSecure123!"),
                "role": "Admin",
                "badge_number": "DF-001",
                "department": "Cyber Directorate Executive"
            },
            {
                "full_name": "Special Agent Alex Cross",
                "email": "alex.cross@forensics.local",
                "password_hash": hash_password("Investigator123!"),
                "role": "Lead Investigator",
                "badge_number": "DF-104",
                "department": "Major Cyber Incidents Taskforce"
            },
            {
                "full_name": "Senior Analyst Elena Rostova",
                "email": "elena.rostova@forensics.local",
                "password_hash": hash_password("Analyst123!"),
                "role": "Forensic Analyst",
                "badge_number": "DF-205",
                "department": "Digital Evidence Lab"
            },
            {
                "full_name": "Inspector Marcus Sterling",
                "email": "marcus.sterling@forensics.local",
                "password_hash": hash_password("Auditor123!"),
                "role": "Auditor",
                "badge_number": "DF-901",
                "department": "Office of Inspector General"
            }
        ]

        created_users = {}
        for u in users_data:
            user = User(**u)
            db.session.add(user)
            created_users[u["email"]] = user

        db.session.commit()
        print(f"Created {len(created_users)} users.")

        admin_user = created_users["admin@forensics.local"]
        lead_user = created_users["alex.cross@forensics.local"]
        analyst_user = created_users["elena.rostova@forensics.local"]
        auditor_user = created_users["marcus.sterling@forensics.local"]

        # 2. Tags
        tags_data = [
            ("Malware Sample", "Executable binary exhibiting malicious capabilities", "#ef4444"),
            ("Ransomware Artifact", "Encryption note, key remnants, or ransomed payloads", "#f97316"),
            ("Volatile Memory", "Live RAM captures, pagefile or hibernation artifacts", "#eab308"),
            ("Disk Clone", "Raw bit-stream image (dd / E01) of physical disk", "#3b82f6"),
            ("Network PCAP", "Network packet capture during malicious command & control", "#06b6d4"),
            ("Mobile Extraction", "Physical or logical dump of mobile device", "#8b5cf6"),
            ("Financial Ledger", "Tampered accounting spreadsheets, logs or databases", "#10b981"),
            ("Cloud Storage Snapshot", "S3 / GCS / Azure bucket snapshot or IAM logs", "#ec4899"),
        ]
        created_tags = {}
        for name, desc, color in tags_data:
            tag = Tag(name=name, description=desc, color_code=color)
            db.session.add(tag)
            created_tags[name] = tag
        db.session.commit()
        print(f"Created {len(created_tags)} tags.")

        # 3. Forensic Tools
        tools_data = [
            ForensicTool(
                name="FTK Imager",
                version="4.7.1",
                vendor="AccessData / Exterro",
                tool_type="Disk Imager",
                is_validated=True,
                notes="NIST CFTT validated bit-stream physical image acquisition software"
            ),
            ForensicTool(
                name="Volatility Framework",
                version="3.2.0",
                vendor="The Volatility Foundation",
                tool_type="Memory Analyzer",
                is_validated=True,
                notes="Memory forensic framework for incident response and malware triage"
            ),
            ForensicTool(
                name="Wireshark Enterprise",
                version="4.2.4",
                vendor="Wireshark Foundation",
                tool_type="Network Analyzer",
                is_validated=True,
                notes="Protocol analyzer for deep packet inspection and SSL/TLS decryption analysis"
            ),
            ForensicTool(
                name="Tableau T8u Forensic USB Bridge",
                version="Hardware Gen 3",
                vendor="OpenText Guidance Software",
                tool_type="Hardware Write Blocker",
                is_validated=True,
                notes="Hardware write-blocking physical unit preventing host OS modification"
            ),
            ForensicTool(
                name="Autopsy Forensic Browser",
                version="4.21.0",
                vendor="Basis Technology",
                tool_type="File Carver",
                is_validated=True,
                notes="Open source digital forensics platform for disk analysis and timeline generation"
            ),
        ]
        for t in tools_data:
            db.session.add(t)
        db.session.commit()
        print(f"Created {len(tools_data)} forensic tools.")

        # 4. Investigations
        cases_data = [
            Investigation(
                case_number="CASE-2026-0812",
                title="Operation Silent Vault: Swift Gateway Infiltration",
                description="Investigating suspected APT infiltration of financial settlement endpoints. Rogue scheduled tasks discovered communicating with overseas C2 infrastructure.",
                status="In Progress",
                priority="Critical",
                investigator_id=lead_user.user_id,
                incident_date=current_time() - timedelta(days=14)
            ),
            Investigation(
                case_number="CASE-2026-0945",
                title="BlackCat Ransomware Attack on Logistics Grid",
                description="Automated ransomware deployed via compromised Domain Controller service account. Encrypted core SCADA dispatch logs.",
                status="In Progress",
                priority="High",
                investigator_id=lead_user.user_id,
                incident_date=current_time() - timedelta(days=7)
            ),
            Investigation(
                case_number="CASE-2026-1014",
                title="Insider IP Theft: Next-Gen Propulsion Schematics",
                description="Departing senior engineer accessed restricted CAD repositories off-hours and transferred compressed archives to unsanctioned external media.",
                status="Open",
                priority="Medium",
                investigator_id=lead_user.user_id,
                incident_date=current_time() - timedelta(days=3)
            )
        ]
        for c in cases_data:
            db.session.add(c)
        db.session.commit()
        print(f"Created {len(cases_data)} investigations.")

        case1, case2, case3 = cases_data

        # 5. Case Notes
        notes = [
            CaseNote(
                investigation_id=case1.investigation_id,
                author_id=lead_user.user_id,
                note_type="Initial Assessment",
                title="Initial Perimeter Breach Vector Identified",
                content="Firewall logs show inbound reverse-shell session initiated from IP 198.51.100.42 to internal host 10.0.4.12 on port 4443.",
                is_confidential=False
            ),
            CaseNote(
                investigation_id=case1.investigation_id,
                author_id=analyst_user.user_id,
                note_type="Timeline Finding",
                title="Persistence Mechanism in Task Scheduler",
                content="Analyzed registry SYSTEM hive. Discovered scheduled task 'SystemDiagnosticsCore' pointing to hidden powershell script in C:\\Windows\\Temp.",
                is_confidential=False
            ),
            CaseNote(
                investigation_id=case2.investigation_id,
                author_id=analyst_user.user_id,
                note_type="Forensic Observation",
                title="Ransomware Binary Header Analysis",
                content="Extracted sample payload. Matches known BlackCat/ALPHV family. Embedded public RSA key detected for per-file AES-GCM wrapping.",
                is_confidential=True
            )
        ]
        for n in notes:
            db.session.add(n)
        db.session.commit()

        # 6. Physical Sample Files and Evidence
        upload_dir = app.config.get("UPLOAD_FOLDER")
        os.makedirs(upload_dir, exist_ok=True)

        samples = [
            {
                "evidence_number": "EVD-2026-0001",
                "evidence_name": "RAM Dump - Primary Domain Controller DC-01",
                "evidence_type": "Memory Dump",
                "description": "32GB physical RAM dump acquired via WinPmem before machine isolation.",
                "filename": "DC01_memdump_core.bin",
                "content": b"WINPMEM_FORENSIC_ACQUISITION_HEADER\x00\x01\x02\x03\x04MEMORY_DUMP_ARTIFACT_AUTHENTIC_2026",
                "mime_type": "application/octet-stream",
                "investigation_id": case1.investigation_id,
                "collected_by": analyst_user.user_id,
                "current_custodian_id": analyst_user.user_id,
                "storage_location": "Secure Cold Vault Shelf B-3",
                "tag_names": ["Volatile Memory", "Malware Sample"],
                "status": "Verified"
            },
            {
                "evidence_number": "EVD-2026-0002",
                "evidence_name": "Forensic Image - Executive Laptop NVMe Drive",
                "evidence_type": "Disk Image",
                "description": "Bit-stream raw clone acquired using Tableau Hardware Write-Blocker.",
                "filename": "Exec_Dell_NVMe_raw.dd",
                "content": b"EXPERT_WITNESS_COMPRESSION_BITSTREAM_RAW_DISK_IMAGE_SECTOR_0000000_CLEAN_EVIDENCE",
                "mime_type": "application/octet-stream",
                "investigation_id": case1.investigation_id,
                "collected_by": lead_user.user_id,
                "current_custodian_id": analyst_user.user_id,
                "storage_location": "Digital Evidence Lab Room 402",
                "tag_names": ["Disk Clone"],
                "status": "In Custody"
            },
            {
                "evidence_number": "EVD-2026-0003",
                "evidence_name": "Edge Gateway PCAP - C2 Beacon Session",
                "evidence_type": "Network PCAP",
                "description": "Full packet capture of perimeter firewall interface during anomalous data exfiltration.",
                "filename": "perimeter_edge_c2_capture.pcap",
                "content": b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00PCAP_FRAME_DATA",
                "mime_type": "application/vnd.tcpdump.pcap",
                "investigation_id": case1.investigation_id,
                "collected_by": analyst_user.user_id,
                "current_custodian_id": analyst_user.user_id,
                "storage_location": "Encrypted Evidence Storage Array SAN-01",
                "tag_names": ["Network PCAP", "Malware Sample"],
                "status": "Verified"
            },
            {
                "evidence_number": "EVD-2026-0004",
                "evidence_name": "SanDisk Ultra 128GB USB Flash Drive Physical Image",
                "evidence_type": "Removable Media",
                "description": "Thumb drive recovered from suspect's desk carrying staged proprietary archives.",
                "filename": "SanDisk_USB_Drive_Clone.raw",
                "content": b"USB_MASS_STORAGE_CONTROLLER_IMAGE_PHYSICAL_RAW_SECTOR_DATA_STAGED_DOCUMENTS",
                "mime_type": "application/octet-stream",
                "investigation_id": case3.investigation_id,
                "collected_by": lead_user.user_id,
                "current_custodian_id": lead_user.user_id,
                "storage_location": "Secure Safe 1, Drawer 4",
                "tag_names": ["Financial Ledger", "Disk Clone"],
                "status": "Collected"
            }
        ]

        created_evidences = []
        for s in samples:
            file_path = os.path.join(upload_dir, s["filename"])
            with open(file_path, "wb") as f:
                f.write(s["content"])

            sha256 = compute_sha256(s["content"])
            size = len(s["content"])

            ev = Evidence(
                evidence_number=s["evidence_number"],
                evidence_name=s["evidence_name"],
                evidence_type=s["evidence_type"],
                description=s["description"],
                file_path=file_path,
                original_filename=s["filename"],
                file_size_bytes=size,
                mime_type=s["mime_type"],
                sha256_hash=sha256,
                status=s["status"],
                storage_location=s["storage_location"],
                investigation_id=s["investigation_id"],
                collected_by=s["collected_by"],
                current_custodian_id=s["current_custodian_id"],
                collected_at=current_time() - timedelta(days=2)
            )

            for tname in s["tag_names"]:
                if tname in created_tags:
                    ev.tags.append(created_tags[tname])

            db.session.add(ev)
            created_evidences.append((ev, sha256))

        db.session.commit()
        print(f"Created {len(created_evidences)} evidence records with on-disk sample files.")

        # 7. Chain of Custody Records
        ev1 = created_evidences[0][0]
        ev2 = created_evidences[1][0]

        coc_records = [
            ChainOfCustody(
                evidence_id=ev2.evidence_id,
                transferred_from=lead_user.user_id,
                transferred_to=analyst_user.user_id,
                transfer_date=current_time() - timedelta(days=1),
                purpose="Forensic bit-stream verification and timeline analysis in Faraday cage lab",
                location="Digital Evidence Laboratory Room 402",
                authorization_notes="Authorized under Search Warrant #SW-2026-991"
            )
        ]
        for c in coc_records:
            db.session.add(c)
        db.session.commit()

        # 8. Integrity Checks
        ic1 = IntegrityCheck(
            evidence_id=ev1.evidence_id,
            checked_by=analyst_user.user_id,
            original_hash=created_evidences[0][1],
            calculated_hash=created_evidences[0][1],
            result="VERIFIED",
            notes="Periodic baseline verification before mounting in read-only sandbox. Hash match 100%.",
            checked_at=current_time() - timedelta(hours=12)
        )
        ic2 = IntegrityCheck(
            evidence_id=created_evidences[2][0].evidence_id,
            checked_by=analyst_user.user_id,
            original_hash=created_evidences[2][1],
            calculated_hash=created_evidences[2][1],
            result="VERIFIED",
            notes="PCAP frame checksum verification passed.",
            checked_at=current_time() - timedelta(hours=6)
        )
        db.session.add_all([ic1, ic2])
        db.session.commit()

        # 9. Tool Usage
        tool1 = ForensicTool.query.filter_by(name="FTK Imager").first()
        usage = EvidenceToolUsage(
            evidence_id=ev2.evidence_id,
            tool_id=tool1.tool_id,
            operator_id=analyst_user.user_id,
            action_type="Bit-stream Acquisition",
            command_executed="ftkimager /dev/nvme0n1 /evidence/Exec_Dell_NVMe_raw.dd --verify --sha256",
            output_summary="Image created with 0 bad sectors. Hardware write-blocker active."
        )
        db.session.add(usage)

        # 10. Evidence Disposition
        disp = EvidenceDisposition(
            evidence_id=ev1.evidence_id,
            requested_by=analyst_user.user_id,
            approved_by=admin_user.user_id,
            disposition_type="Permanent Archive",
            status="Approved",
            reason="Retain raw memory image for 7 years in compliance with Fed. R. Evid. 902(14)",
            legal_authorization="US District Court Protective Order #26-CV-819"
        )
        db.session.add(disp)
        db.session.commit()

        print("Database successfully seeded with realistic forensic records!")

if __name__ == "__main__":
    seed_database()
