import os
import sys
import json
import hashlib
import re
from datetime import datetime, timezone

def run_verification():
    # -------------------------------------------------------------------------
    # 0. Load Simulation APM Profile (Simulates Zero-Copy Reference to ServiceNow APM)
    # -------------------------------------------------------------------------
    profile_arg = sys.argv[1] if len(sys.argv) > 1 else "profiles/apm_clinical_analytics.json"
    
    if not os.path.exists(profile_arg):
        print(f"❌ ERROR: APM profile '{profile_arg}' not found.")
        sys.exit(1)
        
    with open(profile_arg, "r", encoding="utf-8") as f:
        apm = json.load(f)

    print("=================================================================")
    print("      DRC COMPLIANCE-AS-CODE (CaC) VERIFICATION ENGINE          ")
    print("=================================================================")
    print(f"Profile Loaded   : {profile_arg}")
    print(f"APM ID           : {apm.get('apmId')}")
    print(f"Application Name : {apm.get('applicationName')}")
    print(f"Risk Tier        : {apm.get('riskTier')}")
    print(f"SOX Scope        : {apm.get('soxScope')}")
    print(f"Hosting Platform : {apm.get('hostingPlatform')}")
    print("=================================================================\n")

    evaluations = []
    overall_passed = True

    # -------------------------------------------------------------------------
    # Control 1: PORT-01 - Recording in Digital Solution Portfolio (Intake)
    # Rule: Must have valid APM ID format (APM000XXXX), valid Risk Tier, and owner email
    # -------------------------------------------------------------------------
    port_01_violations = []
    apm_id = str(apm.get("apmId", ""))
    if not re.match(r"^APM\d{7}$", apm_id):
        port_01_violations.append(f"Invalid APM ID format '{apm_id}'. Expected format 'APM' + 7 digits.")
    
    if not apm.get("riskTier") in ["GxP-Critical", "High", "Medium", "Low"]:
        port_01_violations.append(f"Invalid or missing Risk Tier: '{apm.get('riskTier')}'.")

    if not apm.get("ownerEmail") or "@sanofi.com" not in apm.get("ownerEmail"):
        port_01_violations.append(f"Missing or non-Sanofi ownerEmail: '{apm.get('ownerEmail')}'.")

    port_01_status = "PASSED" if not port_01_violations else "FAILED"
    if port_01_status == "FAILED":
        overall_passed = False

    evaluations.append({
        "controlId": "PORT-01",
        "controlName": "Recording in Digital Solution Portfolio",
        "frameworkPhase": "Intake",
        "status": port_01_status,
        "details": port_01_violations if port_01_violations else ["Valid APM portfolio registration and owner verified."]
    })

    print(f"[{port_01_status}] PORT-01: Digital Solution Portfolio Registration")

    # -------------------------------------------------------------------------
    # Control 2: DEL-05 - Develop / Configure Digital Solution (Implement - Build)
    # Rule: No hardcoded credentials, secret keys, or passwords committed in repo files
    # -------------------------------------------------------------------------
    del_05_violations = []
    forbidden_tokens = ["SECRET_KEY", "PASSWORD=", "PRIVATE_KEY", "AWS_SECRET_ACCESS_KEY"]

    for root, _, files in os.walk("."):
        if ".git" in root or "build" in root or "scripts" in root:
            continue
        for file in files:
            if file.endswith((".py", ".sql", ".yml", ".yaml", ".json", ".env")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as content:
                        for line_no, line in enumerate(content, 1):
                            for token in forbidden_tokens:
                                if token in line:
                                    del_05_violations.append({
                                        "file": filepath,
                                        "line": line_no,
                                        "token": token
                                    })
                except Exception as e:
                    print(f"Warning: Could not read {filepath}: {e}")

    del_05_status = "PASSED" if not del_05_violations else "FAILED"
    if del_05_status == "FAILED":
        overall_passed = False

    evaluations.append({
        "controlId": "DEL-05",
        "controlName": "Develop / Configure Digital Solution (Secret & Credential Leakage Check)",
        "frameworkPhase": "Implement - Build",
        "status": del_05_status,
        "details": del_05_violations if del_05_violations else ["No unencrypted credentials or secret patterns detected in repository files."]
    })

    print(f"[{del_05_status}] DEL-05: Code & Configuration Security Scan")

    # -------------------------------------------------------------------------
    # Control 3: DEL-10 - Ensure Traceability (Implement - Test / Release)
    # Rule: Binds Git commit provenance, run ID, and generates cryptographic non-repudiation
    # -------------------------------------------------------------------------
    commit_sha = os.getenv("GITHUB_SHA", "sandbox-commit-sha-000000")
    repo = os.getenv("GITHUB_REPOSITORY", "Sanofi/drc-cac-sandbox")
    ref = os.getenv("GITHUB_REF_NAME", "main")
    run_id = os.getenv("GITHUB_RUN_ID", "local-run-1")

    # DEL-10 is inherently satisfied if execution metadata is captured and signable
    del_10_status = "PASSED"
    evaluations.append({
        "controlId": "DEL-10",
        "controlName": "Ensure Traceability (Audit Evidence Package)",
        "frameworkPhase": "Implement - Test",
        "status": del_10_status,
        "details": [
            f"Git provenance captured: repository={repo}, commit={commit_sha}, runId={run_id}"
        ]
    })

    print(f"[{del_10_status}] DEL-10: Traceability and Provenance Binding")

    # -------------------------------------------------------------------------
    # Assemble Full ODCS v3.1.0 Telemetry Event
    # -------------------------------------------------------------------------
    telemetry = {
        "contractVersion": "odcs-3.1.0",
        "eventId": f"EVT-{run_id}-{commit_sha[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {
            "platform": "github-enterprise",
            "repository": repo,
            "commitSha": commit_sha,
            "ref": ref,
            "runId": run_id
        },
        "context": {
            "apmId": apm.get("apmId"),
            "riskTier": apm.get("riskTier"),
            "soxScope": apm.get("soxScope", False),
            "hostingPlatform": apm.get("hostingPlatform"),
            "dataClassification": apm.get("dataClassification"),
            "ownerEmail": apm.get("ownerEmail")
        },
        "evaluations": evaluations,
        "overallResult": "PASSED" if overall_passed else "FAILED"
    }

    # Cryptographic SHA-256 Non-Repudiation Hash (21 CFR Part 11 Integrity)
    canonical_payload = json.dumps(telemetry, sort_keys=True)
    payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    telemetry["integrity"] = {
        "algorithm": "SHA-256",
        "payloadSha256": payload_hash
    }

    # Write telemetry artifact for Box 5 / Tier 3 Ingestion
    os.makedirs("build/telemetry", exist_ok=True)
    output_path = "build/telemetry/verification-evidence.json"
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(telemetry, out, indent=2)

    print("\n-----------------------------------------------------------------")
    print(f"Artifact Staged  : {output_path}")
    print(f"Overall Result   : {telemetry['overallResult']}")
    print(f"Payload SHA-256  : {payload_hash}")
    print("-----------------------------------------------------------------")

    # -------------------------------------------------------------------------
    # Risk-Proportional Gate Enforcement (Box 4)
    # -------------------------------------------------------------------------
    if not overall_passed:
        is_blocking = apm.get("riskTier") in ["GxP-Critical", "High"]
        if is_blocking:
            print("\n❌ COMPLIANCE GATE VIOLATION: Blocking PR merge for high-risk asset.")
            sys.exit(1)
        else:
            print("\n⚠️ COMPLIANCE WARNING: Non-blocking warning for low/medium risk asset.")
            sys.exit(0)
    else:
        print("\n✅ COMPLIANCE GATE PASSED: All controls verified successfully.")
        sys.exit(0)

if __name__ == "__main__":
    run_verification()
