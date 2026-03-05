"""
CyberShield-X Dataset Generator — D2: UEBA User Behavior Dataset
Generates datasets/ueba_behavior.csv with 3000 rows.
"""

import csv
import os
import uuid
import random
import math
from datetime import date, timedelta

random.seed(43)

DEPARTMENTS = ["IT", "Finance", "HR", "Engineering", "Sales", "Legal", "Executive"]
SENIORITY = ["Junior", "Mid", "Senior", "Manager", "Director", "C-Level"]
EMP_STATUS = ["Active", "Active", "Active", "Active", "Probation", "PIP", "Notice_Period"]
DEVICES = ["Corporate_Laptop", "Corporate_Laptop", "Corporate_Laptop", "Personal_Device", "Unregistered"]
LOCATIONS = ["Office", "Office", "Office", "VPN_Home", "VPN_Home", "VPN_Foreign", "Unknown"]
THREAT_CATEGORIES = {
    "CLEAN": 2250, "Curious_Snooping": 240, "Policy_Violation": 210,
    "Data_Theft_Prep": 150, "Active_Data_Theft": 90, "Sabotage": 30, "Credential_Abuse": 30,
}

COLUMNS = [
    "record_id", "user_id", "department", "role_seniority", "employment_status", "date",
    "login_time_hour", "logout_time_hour", "session_duration_hrs",
    "login_location", "device_type", "failed_login_attempts",
    "unique_systems_accessed", "off_hours_access", "weekend_access",
    "files_accessed", "sensitive_files_accessed", "files_downloaded",
    "files_uploaded_external", "data_volume_mb", "print_job_count",
    "email_sent_count", "email_external_ratio", "large_attachment_count",
    "admin_commands_run", "new_user_accounts_created", "permission_changes_made",
    "audit_log_access", "security_tool_disabled", "vpn_usage_hours",
    "peer_comparison_score", "personal_baseline_score", "velocity_score",
    "threat_category", "is_insider_threat", "risk_level", "investigation_required",
]

USERS = []
for i in range(1, 201):
    USERS.append({
        "user_id": f"USER_{i:03d}",
        "department": random.choice(DEPARTMENTS),
        "role_seniority": random.choice(SENIORITY),
        "employment_status": random.choice(EMP_STATUS),
    })

START_DATE = date(2024, 1, 1)
END_DATE = date(2024, 12, 31)

# Designate 3 insider threat storyline users
INSIDER_USERS = ["USER_042", "USER_107", "USER_183"]
INSIDER_START_DAYS = {
    "USER_042": 90,   # starts escalating day 90
    "USER_107": 150,  # starts escalating day 150
    "USER_183": 220,  # starts escalating day 220
}


def gen_row(user, day_offset, threat_cat):
    d = START_DATE + timedelta(days=day_offset)
    is_weekend = d.weekday() >= 5
    is_fin_exec = user["department"] in ("Finance", "Executive")
    is_risky_status = user["employment_status"] in ("PIP", "Notice_Period")

    # Normal baseline
    login_h = max(0, min(23, random.gauss(9.0, 1.5)))
    session = max(0.5, random.gauss(8.0, 1.5))
    logout_h = min(23.9, login_h + session)
    off_hours = login_h < 6 or login_h > 20
    files = random.randint(5, 50)
    sensitive = random.randint(0, 5) if is_fin_exec else random.randint(0, 2)
    downloaded = random.randint(0, 5)
    uploaded_ext = random.randint(0, 1)
    data_mb = round(random.uniform(1, 100), 1)
    email_count = random.randint(5, 50)
    email_ext_ratio = round(random.uniform(0.05, 0.3), 3)
    admin_cmds = 0
    failed_logins = random.randint(0, 1)
    systems = random.randint(3, 8)

    # Threat modifications
    if threat_cat == "Curious_Snooping":
        sensitive += random.randint(5, 15)
        systems += random.randint(3, 10)
        audit_log = random.random() < 0.3
    elif threat_cat == "Policy_Violation":
        off_hours = True
        login_h = random.uniform(22, 23.9)
        uploaded_ext += random.randint(2, 5)
        audit_log = False
    elif threat_cat in ("Data_Theft_Prep", "Active_Data_Theft"):
        sensitive += random.randint(10, 30)
        downloaded += random.randint(10, 50)
        uploaded_ext += random.randint(5, 20)
        data_mb = round(random.uniform(500, 5000), 1)
        email_ext_ratio = round(random.uniform(0.5, 0.9), 3)
        audit_log = random.random() < 0.5
        off_hours = random.random() < 0.6
        if off_hours:
            login_h = random.uniform(22, 23.9)
    elif threat_cat == "Sabotage":
        admin_cmds = random.randint(10, 50)
        systems += random.randint(10, 30)
        failed_logins += random.randint(5, 20)
        audit_log = random.random() < 0.7
    elif threat_cat == "Credential_Abuse":
        admin_cmds = random.randint(5, 30)
        failed_logins += random.randint(10, 50)
        systems += random.randint(10, 25)
        audit_log = random.random() < 0.4
    else:
        audit_log = random.random() < 0.02

    is_threat = threat_cat != "CLEAN"
    risk = "LOW"
    if threat_cat in ("Curious_Snooping", "Policy_Violation"):
        risk = "MEDIUM"
    elif threat_cat in ("Data_Theft_Prep",):
        risk = "HIGH"
    elif threat_cat in ("Active_Data_Theft", "Sabotage", "Credential_Abuse"):
        risk = "CRITICAL"

    peer_score = round(random.uniform(0.0, 0.3), 3) if not is_threat else round(random.uniform(0.5, 1.0), 3)
    baseline_score = round(random.uniform(0.0, 0.2), 3) if not is_threat else round(random.uniform(0.4, 1.0), 3)
    velocity = round(random.uniform(0.0, 0.2), 3) if not is_threat else round(random.uniform(0.3, 1.0), 3)

    return {
        "record_id": str(uuid.uuid4()),
        "user_id": user["user_id"],
        "department": user["department"],
        "role_seniority": user["role_seniority"],
        "employment_status": user["employment_status"],
        "date": d.isoformat(),
        "login_time_hour": round(login_h, 2),
        "logout_time_hour": round(logout_h, 2),
        "session_duration_hrs": round(session, 2),
        "login_location": random.choice(LOCATIONS),
        "device_type": random.choice(DEVICES),
        "failed_login_attempts": failed_logins,
        "unique_systems_accessed": systems,
        "off_hours_access": off_hours,
        "weekend_access": is_weekend,
        "files_accessed": files,
        "sensitive_files_accessed": sensitive,
        "files_downloaded": downloaded,
        "files_uploaded_external": uploaded_ext,
        "data_volume_mb": data_mb,
        "print_job_count": random.randint(0, 5),
        "email_sent_count": email_count,
        "email_external_ratio": email_ext_ratio,
        "large_attachment_count": random.randint(0, 2) if not is_threat else random.randint(0, 8),
        "admin_commands_run": admin_cmds,
        "new_user_accounts_created": 0 if not is_threat else random.randint(0, 3),
        "permission_changes_made": 0 if not is_threat else random.randint(0, 5),
        "audit_log_access": audit_log,
        "security_tool_disabled": random.random() < 0.01 if not is_threat else random.random() < 0.2,
        "vpn_usage_hours": round(random.uniform(0, 4), 1),
        "peer_comparison_score": peer_score,
        "personal_baseline_score": baseline_score,
        "velocity_score": velocity,
        "threat_category": threat_cat,
        "is_insider_threat": is_threat,
        "risk_level": risk,
        "investigation_required": risk in ("HIGH", "CRITICAL"),
    }


def main():
    rows = []
    for threat_cat, count in THREAT_CATEGORIES.items():
        for _ in range(count):
            user = random.choice(USERS)
            day = random.randint(0, 364)
            rows.append(gen_row(user, day, threat_cat))

    random.shuffle(rows)
    outpath = "datasets/ueba_behavior.csv"
    os.makedirs("datasets", exist_ok=True)
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} rows -> {outpath}")


if __name__ == "__main__":
    main()
