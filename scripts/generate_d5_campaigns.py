"""
CyberShield-X Dataset Generator — D5: Attack Campaign & Psychographic Prediction Dataset
Generates datasets/attack_campaigns.csv (1500 rows) and datasets/psychographic_targeting.csv (2000 rows).
"""

import csv
import os
import uuid
import random
from datetime import datetime, timedelta

random.seed(46)

# ─── Attack Campaigns ───────────────────────────────────────
ATTACKER_GROUPS = ["APT28", "APT41", "Lazarus", "FIN7", "Cozy_Bear", "Unknown_Criminal"]
KILL_CHAIN = ["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "ActionOnObj"]
MITRE_TACTICS = ["InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
                 "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
                 "Collection", "CommandAndControl", "Exfiltration", "Impact"]

TECHNIQUES = {
    "Recon": [("T1595", "Active Scanning"), ("T1592", "Gather Victim Host Info"), ("T1589", "Gather Victim Identity Info")],
    "Weaponize": [("T1587", "Develop Capabilities"), ("T1588", "Obtain Capabilities")],
    "Deliver": [("T1566", "Phishing"), ("T1189", "Drive-by Compromise"), ("T1195", "Supply Chain Compromise")],
    "Exploit": [("T1190", "Exploit Public-Facing App"), ("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "Install": [("T1059", "Command and Scripting Interpreter"), ("T1053", "Scheduled Task"), ("T1547", "Boot or Logon Autostart")],
    "C2": [("T1071", "Application Layer Protocol"), ("T1573", "Encrypted Channel"), ("T1105", "Ingress Tool Transfer")],
    "ActionOnObj": [("T1041", "Exfiltration Over C2"), ("T1486", "Data Encrypted for Impact"), ("T1529", "System Shutdown/Reboot")],
}

TOOLS = ["Cobalt Strike", "Mimikatz", "PowerShell", "Custom", "Metasploit", "BloodHound",
         "Impacket", "PsExec", "WMI", "CertUtil", "BITSAdmin"]
TARGETS = ["Workstation", "Server", "DC", "Firewall", "Database", "Email"]
OBJECTIVES = ["DataTheft", "Ransomware", "Espionage", "Destruction", "Persistence"]

CAMP_COLUMNS = [
    "campaign_id", "step_number", "timestamp", "attacker_group",
    "kill_chain_stage", "mitre_tactic", "mitre_technique_id", "technique_name",
    "tool_used", "target_system", "source_ip", "success",
    "dwell_time_days", "detection_evaded", "objective",
]

START_DATE = datetime(2024, 1, 1)


def gen_campaign(camp_id):
    rows = []
    group = random.choice(ATTACKER_GROUPS)
    objective = random.choice(OBJECTIVES)
    src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    is_sophisticated = group in ("APT28", "APT41", "Lazarus", "Cozy_Bear")
    success_rate = 0.90 if is_sophisticated else 0.70
    start_ts = START_DATE + timedelta(days=random.randint(0, 300))
    num_steps = random.randint(5, 15)

    for step in range(1, num_steps + 1):
        stage_idx = min(step - 1, len(KILL_CHAIN) - 1)
        # Progress through kill chain
        if step <= len(KILL_CHAIN):
            stage = KILL_CHAIN[stage_idx]
        else:
            stage = random.choice(KILL_CHAIN[3:])  # Later stages

        tech_id, tech_name = random.choice(TECHNIQUES[stage])
        tactic = random.choice(MITRE_TACTICS)
        ts = start_ts + timedelta(minutes=random.randint(5, 480) * step)
        dwell = (ts - start_ts).days

        rows.append({
            "campaign_id": f"CAMP_{camp_id:03d}",
            "step_number": step,
            "timestamp": ts.isoformat(),
            "attacker_group": group,
            "kill_chain_stage": stage,
            "mitre_tactic": tactic,
            "mitre_technique_id": tech_id,
            "technique_name": tech_name,
            "tool_used": random.choice(TOOLS),
            "target_system": random.choice(TARGETS),
            "source_ip": src_ip,
            "success": random.random() < success_rate,
            "dwell_time_days": dwell,
            "detection_evaded": random.random() < (0.8 if is_sophisticated else 0.4),
            "objective": objective,
        })
    return rows


# ─── Psychographic Targeting ────────────────────────────────
DEPARTMENTS = ["IT", "Finance", "HR", "Engineering", "Sales", "Legal", "Executive"]
SENIORITY = ["Junior", "Mid", "Senior", "Manager", "Director", "C-Level"]
TITLES = ["Software Engineer", "Finance Analyst", "HR Manager", "VP Engineering",
          "Sales Director", "Legal Counsel", "CFO", "CISO", "CTO", "IT Admin",
          "Data Scientist", "Product Manager", "DevOps Engineer", "Accountant"]
ATTACK_TYPES = ["Phishing", "Spear_Phishing", "Vishing", "BEC", "Physical"]
INTERVENTIONS = ["Training", "Extra_MFA", "Manager_Brief", "Decoy_Profile"]

PSYCH_COLUMNS = [
    "profile_id", "user_id", "assessment_date", "job_title", "department", "seniority",
    "financial_authority", "admin_access_level", "data_access_level", "org_chart_position",
    "linkedin_profile_public", "linkedin_connections", "recent_role_change",
    "conference_speaker", "email_publicly_listed", "social_media_activity",
    "calendar_density_7d", "recent_org_change", "quarter_end_proximity",
    "recent_bad_performance_review", "security_training_days_ago",
    "targeting_probability_7d", "targeting_probability_30d",
    "most_likely_attack_type", "recommended_intervention",
    "was_attacked_in_period",
]

ACCESS_LEVELS = ["None", "Local", "Domain", "Cloud", "All"]
DATA_LEVELS = ["Public", "Internal", "Confidential", "Secret"]
SOCIAL = ["None", "Low", "Medium", "High"]


def gen_psych_row():
    dept = random.choice(DEPARTMENTS)
    sen = random.choice(SENIORITY)
    is_high_value = sen in ("Director", "C-Level") or dept in ("Finance", "Executive")

    financial_auth = is_high_value or random.random() < 0.1
    admin_lvl = random.choice(ACCESS_LEVELS)
    if dept == "IT":
        admin_lvl = random.choice(["Local", "Domain", "Cloud", "All"])
    data_lvl = random.choice(DATA_LEVELS)
    if is_high_value:
        data_lvl = random.choice(["Confidential", "Secret"])
    org_pos = round(random.uniform(0.7, 1.0), 2) if is_high_value else round(random.uniform(0.0, 0.5), 2)

    linkedin_pub = random.random() < 0.7
    linkedin_conn = random.randint(50, 500) if linkedin_pub else 0
    role_change = random.random() < 0.1
    speaker = random.random() < 0.15
    email_pub = random.random() < 0.3
    social = random.choice(SOCIAL)

    cal_density = round(random.uniform(0.3, 1.0), 2) if is_high_value else round(random.uniform(0.1, 0.7), 2)
    org_change = random.random() < 0.15
    qtr_end = random.random() < 0.17  # ~2/12 months
    bad_review = random.random() < 0.08
    training_ago = random.randint(1, 365)

    # Risk calculations
    authority_score = (1 if financial_auth else 0) + ACCESS_LEVELS.index(admin_lvl) / 4 + DATA_LEVELS.index(data_lvl) / 3
    access_score = (1 if linkedin_pub else 0) * 0.3 + (1 if email_pub else 0) * 0.3 + (1 if speaker else 0) * 0.2 + SOCIAL.index(social) / 3 * 0.2
    stress_score = cal_density * 0.3 + (1 if org_change else 0) * 0.2 + (1 if qtr_end else 0) * 0.2 + (1 if bad_review else 0) * 0.3
    temporal_risk = (1 if role_change else 0) * 0.5 + (1 if qtr_end else 0) * 0.3 + (1 / max(training_ago, 1)) * 100 * 0.2

    base_risk = (authority_score * 0.35 + access_score * 0.25 + stress_score * 0.25 + min(temporal_risk, 1) * 0.15)
    risk_7d = round(min(1.0, base_risk * random.uniform(0.8, 1.2) * 0.8), 3)
    risk_30d = round(min(1.0, base_risk * random.uniform(0.9, 1.1)), 3)

    attacked = risk_30d > 0.5 and random.random() < risk_30d
    attack_type = "Spear_Phishing" if is_high_value else random.choice(ATTACK_TYPES)

    if risk_30d > 0.9:
        intervention = "Decoy_Profile"
    elif risk_30d > 0.8:
        intervention = "Manager_Brief"
    elif risk_30d > 0.7:
        intervention = "Extra_MFA"
    else:
        intervention = "Training"

    return {
        "profile_id": str(uuid.uuid4()),
        "user_id": f"USER_{random.randint(1,200):03d}",
        "assessment_date": (datetime(2024, 1, 1) + timedelta(days=random.randint(0, 364))).date().isoformat(),
        "job_title": random.choice(TITLES),
        "department": dept,
        "seniority": sen,
        "financial_authority": financial_auth,
        "admin_access_level": admin_lvl,
        "data_access_level": data_lvl,
        "org_chart_position": org_pos,
        "linkedin_profile_public": linkedin_pub,
        "linkedin_connections": linkedin_conn,
        "recent_role_change": role_change,
        "conference_speaker": speaker,
        "email_publicly_listed": email_pub,
        "social_media_activity": social,
        "calendar_density_7d": cal_density,
        "recent_org_change": org_change,
        "quarter_end_proximity": qtr_end,
        "recent_bad_performance_review": bad_review,
        "security_training_days_ago": training_ago,
        "targeting_probability_7d": risk_7d,
        "targeting_probability_30d": risk_30d,
        "most_likely_attack_type": attack_type,
        "recommended_intervention": intervention,
        "was_attacked_in_period": attacked,
    }


def main():
    # Attack Campaigns
    camp_rows = []
    for i in range(1, 151):
        camp_rows.extend(gen_campaign(i))
    # Trim or pad to ~1500
    random.shuffle(camp_rows)
    camp_rows = camp_rows[:1500]

    os.makedirs("datasets", exist_ok=True)
    with open("datasets/attack_campaigns.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CAMP_COLUMNS)
        writer.writeheader()
        writer.writerows(camp_rows)
    print(f"Generated {len(camp_rows)} rows -> datasets/attack_campaigns.csv")

    # Psychographic Targeting
    psych_rows = [gen_psych_row() for _ in range(2000)]
    random.shuffle(psych_rows)

    with open("datasets/psychographic_targeting.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PSYCH_COLUMNS)
        writer.writeheader()
        writer.writerows(psych_rows)
    print(f"Generated {len(psych_rows)} rows -> datasets/psychographic_targeting.csv")


if __name__ == "__main__":
    main()
