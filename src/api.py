from flask import Flask, jsonify, request, Response
from datetime import datetime
from flask_cors import CORS
from ml_model import predict_risk
from live_logs import generate_log

import sqlite3
import csv
import os
import boto3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)


# ================================================================
# HOME
# ================================================================

@app.route("/")
def home():
    return "Cloud Security API Running"


# ================================================================
# LIVE LOGS
# ================================================================

@app.route("/logs")
def get_logs():
    log = generate_log()
    return jsonify(log)


# ================================================================
# SIGNUP
# ================================================================

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)

    username = data.get("username")
    password = generate_password_hash(data.get("password"))
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, password, created_at)
        )
        conn.commit()
        return jsonify({"message": "User created"})
    except:
        return jsonify({"error": "User already exists"})
    finally:
        conn.close()


@app.route("/users", methods=["GET"])
def get_users():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, created_at FROM users")
    users = cursor.fetchall()
    conn.close()

    result = []
    for user in users:
        result.append({
            "id": user[0],
            "username": user[1],
            "created_at": user[2]
        })

    return jsonify(result)


# ================================================================
# LOGIN
# ================================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Account not created"})

    if not check_password_hash(user[0], password):
        return jsonify({"error": "Incorrect password"})

    return jsonify({"message": "Login successful"})


# ================================================================
# RISK CLASSIFICATION HELPER
# ================================================================

# Only the most meaningless internal AWS housekeeping events are ignored.
# Do NOT add legitimate service events here — the goal is a full dashboard.
IGNORED_EVENTS = {
    "LookupEvents",
    "GetAccountPlanState",
    "GetAccountColor",
    "ListManagedNotificationEvents",
}

# Exact event name → (risk level, human-readable reason)
RISK_MAP = {
    # ── CRITICAL: destructive / irreversible ──────────────────────────────────
    "DeleteBucket":                     ("CRITICAL", "Dangerous resource deletion detected"),
    "DeleteObjects":                    ("CRITICAL", "Bulk S3 object deletion detected"),
    "DeleteUser":                       ("CRITICAL", "IAM user deleted — critical identity change"),
    "DeleteRole":                       ("CRITICAL", "IAM role deleted — critical access change"),
    "DeletePolicy":                     ("CRITICAL", "IAM policy deleted — permissions impacted"),
    "DeleteAccessKey":                  ("CRITICAL", "Access key deleted — credential change detected"),
    "DeleteGroup":                      ("CRITICAL", "IAM group deleted"),
    "DeleteInstanceProfile":            ("CRITICAL", "Instance profile deleted"),
    "DeleteLoginProfile":               ("CRITICAL", "Console login profile deleted"),
    "DeleteVpc":                        ("CRITICAL", "VPC deleted — network impact"),
    "DeleteSubnet":                     ("CRITICAL", "Subnet deleted — network impact"),
    "DeleteSecurityGroup":              ("CRITICAL", "Security group deleted"),
    "TerminateInstances":               ("CRITICAL", "EC2 instances terminated"),
    "DeleteDBInstance":                 ("CRITICAL", "RDS database instance deleted"),
    "DeleteTrail":                      ("CRITICAL", "CloudTrail trail deleted — audit gap risk"),
    "StopLogging":                      ("CRITICAL", "CloudTrail logging stopped — blind spot created"),

    # ── HIGH: authentication, privilege escalation, key management ───────────
    "ConsoleLogin":                     ("HIGH", "Console login activity detected"),
    "AssumeRole":                       ("HIGH", "Role assumption — possible privilege escalation"),
    "AssumeRoleWithWebIdentity":        ("HIGH", "Web identity role assumption detected"),
    "AssumeRoleWithSAML":               ("HIGH", "SAML role assumption detected"),
    "CreateAccessKey":                  ("HIGH", "New access key created — monitor for misuse"),
    "UpdateAccessKey":                  ("HIGH", "Access key status changed"),
    "AttachUserPolicy":                 ("HIGH", "Policy attached to user — permission escalation risk"),
    "DetachUserPolicy":                 ("HIGH", "Policy detached from user — permission change"),
    "AttachRolePolicy":                 ("HIGH", "Policy attached to role — escalation risk"),
    "DetachRolePolicy":                 ("HIGH", "Policy detached from role"),
    "AttachGroupPolicy":                ("HIGH", "Policy attached to group"),
    "DetachGroupPolicy":                ("HIGH", "Policy detached from group"),
    "PutRolePolicy":                    ("HIGH", "Inline policy added to role"),
    "UpdateAssumeRolePolicy":           ("HIGH", "Role trust policy modified"),
    "AddUserToGroup":                   ("HIGH", "User added to IAM group — review group permissions"),
    "RemoveUserFromGroup":              ("HIGH", "User removed from IAM group"),
    "CreateLoginProfile":               ("HIGH", "Console login profile created for IAM user"),
    "UpdateLoginProfile":               ("HIGH", "IAM user password changed"),
    "GetSecretValue":                   ("HIGH", "Secret accessed from Secrets Manager"),
    "AuthorizeSecurityGroupIngress":    ("HIGH", "Inbound firewall rule added"),
    "AuthorizeSecurityGroupEgress":     ("HIGH", "Outbound firewall rule added"),
    "RevokeSecurityGroupIngress":       ("HIGH", "Inbound firewall rule removed"),
    "ModifyInstanceAttribute":          ("HIGH", "EC2 instance attribute modified"),

    # ── MEDIUM: resource creation / configuration changes ────────────────────
    "CreateBucket":                     ("MEDIUM", "New S3 bucket created — verify access controls"),
    "PutBucketPolicy":                  ("MEDIUM", "S3 bucket policy updated"),
    "PutBucketAcl":                     ("MEDIUM", "S3 bucket ACL changed"),
    "CreateUser":                       ("MEDIUM", "New IAM user created — review permissions"),
    "CreateRole":                       ("MEDIUM", "New IAM role created — review trust policy"),
    "CreatePolicy":                     ("MEDIUM", "New IAM policy created — review permissions"),
    "CreatePolicyVersion":              ("MEDIUM", "New IAM policy version created"),
    "PutUserPolicy":                    ("MEDIUM", "Inline policy applied to user — review scope"),
    "CreateGroup":                      ("MEDIUM", "New IAM group created"),
    "CreateInstanceProfile":            ("MEDIUM", "Instance profile created"),
    "RunInstances":                     ("MEDIUM", "New EC2 instances launched"),
    "StartInstances":                   ("MEDIUM", "EC2 instances started"),
    "StopInstances":                    ("MEDIUM", "EC2 instances stopped"),
    "RebootInstances":                  ("MEDIUM", "EC2 instances rebooted"),
    "CreateSecurityGroup":              ("MEDIUM", "New security group created"),
    "CreateVpc":                        ("MEDIUM", "New VPC created"),
    "CreateSubnet":                     ("MEDIUM", "New subnet created"),
    "AllocateAddress":                  ("MEDIUM", "Elastic IP allocated"),
    "CreateInternetGateway":            ("MEDIUM", "Internet gateway created"),
    "CreateDBInstance":                 ("MEDIUM", "New RDS database instance created"),
    "CreateSnapshot":                   ("MEDIUM", "EBS snapshot created"),
    "CreateKeyPair":                    ("MEDIUM", "New EC2 key pair created"),
    "ImportKeyPair":                    ("MEDIUM", "EC2 key pair imported"),
    "PutBucketVersioning":              ("MEDIUM", "S3 bucket versioning configuration changed"),
    "PutBucketLogging":                 ("MEDIUM", "S3 bucket logging configuration changed"),
    "CreateFunction20150331":           ("MEDIUM", "Lambda function created"),
    "UpdateFunctionCode20150331v2":     ("MEDIUM", "Lambda function code updated"),
    "CreateStack":                      ("MEDIUM", "CloudFormation stack created"),
    "UpdateStack":                      ("MEDIUM", "CloudFormation stack updated"),
    "CreateSecret":                     ("MEDIUM", "New secret created in Secrets Manager"),
    "UpdateSecret":                     ("MEDIUM", "Secret updated in Secrets Manager"),
    "PutMetricAlarm":                   ("MEDIUM", "CloudWatch alarm created or updated"),

    # ── LOW: read-only / informational ───────────────────────────────────────
    "ListUsers":                        ("LOW", "Read-only operation: ListUsers"),
    "ListAccessKeys":                   ("LOW", "Read-only operation: ListAccessKeys"),
    "ListBuckets":                      ("LOW", "Read-only operation: ListBuckets"),
    "ListRoles":                        ("LOW", "Read-only operation: ListRoles"),
    "ListPolicies":                     ("LOW", "Read-only operation: ListPolicies"),
    "ListGroups":                       ("LOW", "Read-only operation: ListGroups"),
    "ListInstances":                    ("LOW", "Read-only operation: ListInstances"),
    "GetUser":                          ("LOW", "Read-only operation: GetUser"),
    "GetRole":                          ("LOW", "Read-only operation: GetRole"),
    "GetPolicy":                        ("LOW", "Read-only operation: GetPolicy"),
    "GetBucketAcl":                     ("LOW", "Read-only operation: GetBucketAcl"),
    "GetBucketPolicy":                  ("LOW", "Read-only operation: GetBucketPolicy"),
    "GetBucketLocation":                ("LOW", "Read-only operation: GetBucketLocation"),
    "DescribeInstances":                ("LOW", "Read-only operation: DescribeInstances"),
    "DescribeSecurityGroups":           ("LOW", "Read-only operation: DescribeSecurityGroups"),
    "DescribeVpcs":                     ("LOW", "Read-only operation: DescribeVpcs"),
    "DescribeSubnets":                  ("LOW", "Read-only operation: DescribeSubnets"),
    "DescribeImages":                   ("LOW", "Read-only operation: DescribeImages"),
    "DescribeAvailabilityZones":        ("LOW", "Read-only operation: DescribeAvailabilityZones"),
    "DescribeRegions":                  ("LOW", "Read-only operation: DescribeRegions"),
    "ListDelegatedAdministrators":      ("LOW", "Read-only operation: ListDelegatedAdministrators"),
    "DescribeOrganization":             ("LOW", "Read-only operation: DescribeOrganization"),
    "ListAccounts":                     ("LOW", "Read-only operation: ListAccounts"),
    "GetCallerIdentity":                ("LOW", "Read-only operation: GetCallerIdentity"),
}


def calculate_risk(event_name: str) -> tuple:
    """
    Return (risk_level, reason) for a given CloudTrail event name.

    Priority:
      1. Exact match in RISK_MAP
      2. Keyword-based fallback (catches unmapped Delete/Create/List variants)
      3. Default LOW
    """
    # 1. Exact match
    if event_name in RISK_MAP:
        return RISK_MAP[event_name]

    lower = event_name.lower()

    # 2. Keyword fallback
    if "delete" in lower or "terminate" in lower or "remove" in lower:
        return ("CRITICAL", "Deletion or termination action detected — review immediately")

    if "login" in lower:
        return ("HIGH", "Login activity detected")

    if "assume" in lower:
        return ("HIGH", "Role assumption event detected")

    if "accesskey" in lower or "secretkey" in lower:
        return ("HIGH", "Credential key operation detected")

    if "attachpolicy" in lower or "detachpolicy" in lower or "putpolicy" in lower:
        return ("HIGH", "IAM policy change detected")

    if "create" in lower or "put" in lower or "update" in lower or "modify" in lower or "run" in lower or "start" in lower or "stop" in lower or "import" in lower or "allocate" in lower:
        return ("MEDIUM", f"Resource change detected: {event_name}")

    if "list" in lower or "describe" in lower or "get" in lower or "head" in lower:
        return ("LOW", f"Read-only operation: {event_name}")

    # 3. Default
    return ("LOW", f"Detected activity: {event_name}")


# ================================================================
# AWS CLOUDTRAIL ANALYZE
# ================================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Fetch and classify recent CloudTrail events for the security dashboard.

    Design decisions:
      - 4 pages × 50 events = up to 200 raw events fetched.
      - Only the small IGNORED_EVENTS set is dropped; everything else is kept
        so the dashboard shows a realistic, varied mix of event types.
      - Events are split into HIGH/CRITICAL/MEDIUM (priority) and LOW (fill).
      - Final response: all priority events + enough LOW events to reach ~50
        total cards, giving the dashboard a full, professional appearance.
      - Sorted newest-first.
    """
    print("➡ /analyze API HIT")

    data = request.get_json(force=True)

    access_key = data.get("access_key") or data.get("aws_access_key")
    secret_key = data.get("secret_key") or data.get("aws_secret_key")

    if not access_key or not secret_key:
        return jsonify({"error": "Missing AWS credentials"}), 400

    try:
        # ── 1. Build CloudTrail client ───────────────────────────────────────
        region = data.get("region", "ap-south-1")

        client = boto3.client(
              "cloudtrail",
             aws_access_key_id=access_key,
             aws_secret_access_key=secret_key,
             region_name=region
        )

        # ── 2. Paginate: 4 calls × 50 = up to 200 raw events ────────────────
        # AWS hard-caps LookupEvents at 50 per call.
        # 4 pages gives plenty of history without excessive latency.
        raw_events = []
        next_token = None
        MAX_PAGES = 4
        PAGE_SIZE = 50

        for page_num in range(MAX_PAGES):
            kwargs = {"MaxResults": PAGE_SIZE}
            if next_token:
                kwargs["NextToken"] = next_token

            response = client.lookup_events(**kwargs)
            page_events = response.get("Events", [])
            raw_events.extend(page_events)

            print(f"  Page {page_num + 1}: got {len(page_events)} events (total so far: {len(raw_events)})")

            next_token = response.get("NextToken")
            if not next_token:
                break  # fewer events exist than our page budget

        print(f"✅ Total raw events fetched: {len(raw_events)}")

        # ── 3. Classify all events, dropping only true noise ─────────────────
        priority_events = []   # CRITICAL / HIGH / MEDIUM
        low_events = []        # LOW — kept as filler for a full dashboard

        for event in raw_events:
            event_name = event.get("EventName", "Unknown")

            # Drop only the tiny set of meaningless internal events
            if event_name in IGNORED_EVENTS:
                continue

            event_time = event.get("EventTime")
            formatted_time = (
                event_time.strftime("%Y-%m-%d %H:%M:%S")
                if event_time else "N/A"
            )

            risk, reason = calculate_risk(event_name)

            record = {
                "event":       event_name,
                "description": event_name,
                "user":        event.get("Username", "N/A"),
                "time":        formatted_time,
                "location":    "AWS",
                "risk":        risk,
                "reason":      reason,
            }

            if risk == "LOW":
                low_events.append(record)
            else:
                priority_events.append(record)

        print(f"  Priority events (CRITICAL/HIGH/MEDIUM): {len(priority_events)}")
        print(f"  LOW events available as filler:         {len(low_events)}")

        # ── 4. Build final result set ─────────────────────────────────────────
        # Always include all priority events.
        # Pad with LOW events so the dashboard reaches ~50 cards and looks full.
        TARGET_TOTAL = 50
        filler_needed = max(0, TARGET_TOTAL - len(priority_events))
        results = priority_events + low_events[:filler_needed]

        # If we have nothing at all (brand-new / empty AWS account), return
        # whatever raw LOW events exist rather than an empty list.
        if not results:
            results = low_events[:TARGET_TOTAL]

        # ── 5. Sort newest-first ──────────────────────────────────────────────
        results.sort(key=lambda x: x["time"], reverse=True)

        print(f"✅ Events returned to frontend: {len(results)}")
        return jsonify(results)

    except Exception as e:
        print(f"❌ AWS ERROR: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ================================================================
# FILE SCAN
# ================================================================

@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files.get("file")

    if not file:
        return jsonify({"error": "No file uploaded"})

    try:
        content = file.read().decode(errors="ignore").lower()
    except:
        return jsonify({"error": "Unable to read file"})

    suspicious_keywords = [
        "login", "password", "verify", "bank", "otp",
        "urgent", "click here", "reset password"
    ]
    suspicious_links = ["http://"]

    found = []
    score = 0

    for word in suspicious_keywords:
        if word in content:
            found.append(word)
            score += 1

    for link in suspicious_links:
        if link in content:
            found.append(link)
            score += 2

    risk = "MALICIOUS" if score >= 2 else "SAFE"

    return jsonify({
        "risk": risk,
        "found_keywords": found,
        "score": score
    })


# ================================================================
# CSV DOWNLOAD REPORT
# ================================================================

@app.route("/download-report", methods=["POST"])
def download_report():
    data = request.get_json(force=True)
    logs = data.get("logs", [])

    def generate():
        yield "event,user,time,location,risk,reason\n"
        for log in logs:
            yield (
                f"{log.get('event')},"
                f"{log.get('user')},"
                f"{log.get('time')},"
                f"{log.get('location')},"
                f"{log.get('risk')},"
                f"{log.get('reason')}\n"
            )

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=report.csv"},
    )


# ================================================================
# IAM AUDIT
# ================================================================

@app.route("/iam-audit", methods=["POST"])
def iam_audit():
    data = request.get_json(force=True)

    access_key = data.get("aws_access_key")
    secret_key = data.get("aws_secret_key")

    try:
        iam = boto3.client(
            "iam",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        users = iam.list_users()
        results = []

        for user in users["Users"]:
            username = user["UserName"]

            access_keys = iam.list_access_keys(UserName=username)
            key_count = len(access_keys["AccessKeyMetadata"])

            risk = "LOW"
            reason = "User is safe"

            if key_count > 1:
                risk = "HIGH"
                reason = "Multiple access keys detected"

            results.append({
                "user":   username,
                "keys":   key_count,
                "risk":   risk,
                "reason": reason,
            })

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)})


# ================================================================
# RUN
# ================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
