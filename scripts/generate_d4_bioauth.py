"""
CyberShield-X Dataset Generator — D4: Bio-Cyber Fusion Authentication Dataset
Generates datasets/bio_auth_signals.csv with 4000 rows.
"""

import csv
import os
import uuid
import random
import math

random.seed(45)

COLUMNS = [
    "session_id", "user_id", "timestamp", "is_genuine_user", "impostor_type",
    "ecg_rr_interval_mean", "ecg_rr_interval_std", "ecg_qrs_duration_ms",
    "ecg_qt_interval_ms", "ecg_p_wave_amplitude", "ecg_t_wave_polarity",
    "ecg_cardiac_fingerprint_dist",
    "ks_dwell_time_mean", "ks_dwell_time_std", "ks_flight_time_mean",
    "ks_flight_time_std", "ks_digraph_latency_mean", "ks_micro_tremor_freq",
    "ks_micro_tremor_amplitude", "ks_typing_speed_wpm", "ks_error_rate",
    "ks_baseline_cosine_sim",
    "mouse_velocity_mean", "mouse_acceleration_pattern",
    "mouse_hesitation_count", "mouse_path_linearity",
    "ecg_match_score", "keystroke_match_score", "behavioral_match_score",
    "fused_trust_score",
    "auth_decision", "is_legitimate_access", "risk_flags",
]

NUM_USERS = 100
NUM_ROWS = 4000

# Generate per-user biometric baselines
USER_BASELINES = {}
for i in range(1, NUM_USERS + 1):
    uid = f"USER_{i:03d}"
    USER_BASELINES[uid] = {
        "ecg_rr_mean": random.uniform(700, 1000),
        "ecg_rr_std": random.uniform(20, 60),
        "ecg_qrs": random.uniform(60, 120),
        "ecg_qt": random.uniform(350, 450),
        "ecg_p_amp": random.uniform(0.1, 0.3),
        "ecg_t_pol": random.choice([-1, 0, 1]),
        "ks_dwell": random.uniform(70, 150),
        "ks_flight": random.uniform(80, 200),
        "ks_digraph": random.uniform(100, 250),
        "ks_tremor_freq": random.uniform(0.3, 1.5),
        "ks_tremor_amp": random.uniform(0.01, 0.1),
        "ks_wpm": random.uniform(40, 100),
        "mouse_vel": random.uniform(200, 800),
        "mouse_accel": random.uniform(0.3, 0.9),
        "mouse_linearity": random.uniform(0.5, 0.95),
    }

from datetime import datetime, timedelta
START = datetime(2024, 1, 1)


def gen_row(genuine=True, impostor_type="NONE"):
    uid = f"USER_{random.randint(1, NUM_USERS):03d}"
    base = USER_BASELINES[uid]
    ts = START + timedelta(seconds=random.randint(0, 31536000))

    if genuine:
        noise = lambda v, pct=0.05: v + random.gauss(0, v * pct)
        ecg_rr_mean = round(noise(base["ecg_rr_mean"]), 1)
        ecg_rr_std = round(noise(base["ecg_rr_std"]), 1)
        ecg_qrs = round(noise(base["ecg_qrs"]), 1)
        ecg_qt = round(noise(base["ecg_qt"]), 1)
        ecg_p = round(noise(base["ecg_p_amp"]), 4)
        ecg_t = base["ecg_t_pol"]
        ecg_dist = round(random.uniform(0.01, 0.15), 3)

        ks_dwell = round(noise(base["ks_dwell"]), 1)
        ks_dwell_std = round(random.uniform(5, 20), 1)
        ks_flight = round(noise(base["ks_flight"]), 1)
        ks_flight_std = round(random.uniform(10, 30), 1)
        ks_digraph = round(noise(base["ks_digraph"]), 1)
        ks_tremor_f = round(noise(base["ks_tremor_freq"]), 3)
        ks_tremor_a = round(noise(base["ks_tremor_amp"]), 4)
        ks_wpm = round(noise(base["ks_wpm"]), 1)
        ks_err = round(random.uniform(0.01, 0.08), 3)
        ks_cos = round(random.uniform(0.85, 0.99), 3)

        mouse_vel = round(noise(base["mouse_vel"]), 1)
        mouse_accel = round(noise(base["mouse_accel"]), 3)
        mouse_hes = random.randint(0, 3)
        mouse_lin = round(noise(base["mouse_linearity"], 0.03), 3)

        ecg_score = round(random.uniform(0.85, 0.99), 3)
        ks_score = round(random.uniform(0.82, 0.99), 3)
        beh_score = round(random.uniform(0.80, 0.98), 3)
    else:
        # Impostor — different biometric patterns
        if impostor_type == "CREDENTIAL_THEFT":
            ecg_rr_mean = round(random.uniform(600, 1100), 1)
            ecg_rr_std = round(random.uniform(40, 100), 1)
            ecg_qrs = round(random.uniform(60, 120), 1)
            ecg_qt = round(random.uniform(350, 450), 1)
            ecg_p = round(random.uniform(0.05, 0.35), 4)
            ecg_t = random.choice([-1, 0, 1])
            ecg_dist = round(random.uniform(0.6, 0.95), 3)
            ks_cos = round(random.uniform(0.20, 0.50), 3)
            ecg_score = round(random.uniform(0.05, 0.20), 3)
            ks_score = round(random.uniform(0.20, 0.50), 3)
            beh_score = round(random.uniform(0.15, 0.45), 3)
        elif impostor_type == "DEEPFAKE_BIO":
            ecg_rr_mean = round(base["ecg_rr_mean"] + random.gauss(0, 50), 1)
            ecg_rr_std = round(random.uniform(10, 30), 1)
            ecg_qrs = round(base["ecg_qrs"] + random.gauss(0, 10), 1)
            ecg_qt = round(base["ecg_qt"] + random.gauss(0, 15), 1)
            ecg_p = round(random.uniform(0.1, 0.3), 4)
            ecg_t = base["ecg_t_pol"]
            ecg_dist = round(random.uniform(0.3, 0.6), 3)
            ks_cos = round(random.uniform(0.40, 0.65), 3)
            ecg_score = round(random.uniform(0.30, 0.55), 3)
            ks_score = round(random.uniform(0.35, 0.60), 3)
            beh_score = round(random.uniform(0.30, 0.55), 3)
        else:  # COERCED_USER
            ecg_rr_mean = round(base["ecg_rr_mean"] - random.uniform(50, 150), 1)  # stress
            ecg_rr_std = round(base["ecg_rr_std"] * random.uniform(1.5, 3.0), 1)   # high variability
            ecg_qrs = round(base["ecg_qrs"] + random.gauss(0, 5), 1)
            ecg_qt = round(base["ecg_qt"] + random.gauss(0, 10), 1)
            ecg_p = round(base["ecg_p_amp"] * random.uniform(0.8, 1.2), 4)
            ecg_t = base["ecg_t_pol"]
            ecg_dist = round(random.uniform(0.2, 0.4), 3)
            ks_cos = round(random.uniform(0.65, 0.80), 3)
            ecg_score = round(random.uniform(0.50, 0.72), 3)
            ks_score = round(random.uniform(0.60, 0.78), 3)
            beh_score = round(random.uniform(0.55, 0.75), 3)

        ks_dwell = round(random.uniform(50, 200), 1)
        ks_dwell_std = round(random.uniform(15, 50), 1)
        ks_flight = round(random.uniform(60, 300), 1)
        ks_flight_std = round(random.uniform(20, 60), 1)
        ks_digraph = round(random.uniform(80, 350), 1)
        ks_tremor_f = round(random.uniform(0.1, 2.0), 3)
        ks_tremor_a = round(random.uniform(0.005, 0.15), 4)
        ks_wpm = round(random.uniform(20, 120), 1)
        ks_err = round(random.uniform(0.05, 0.25), 3)
        mouse_vel = round(random.uniform(100, 1000), 1)
        mouse_accel = round(random.uniform(0.1, 1.0), 3)
        mouse_hes = random.randint(3, 15)
        mouse_lin = round(random.uniform(0.2, 0.7), 3)

    fused = round(0.4 * ecg_score + 0.35 * ks_score + 0.25 * beh_score, 3)

    if fused >= 0.85:
        decision = "ALLOW"
    elif fused >= 0.70:
        decision = "STEP_UP_MFA"
    else:
        decision = "BLOCK"

    risk_flags = []
    if ecg_score < 0.5:
        risk_flags.append("ECG_MISMATCH")
    if ks_score < 0.5:
        risk_flags.append("KEYSTROKE_DEVIATION")
    if beh_score < 0.5:
        risk_flags.append("BEHAVIORAL_ANOMALY")
    if mouse_hes > 8:
        risk_flags.append("MOUSE_HESITATION")

    return {
        "session_id": str(uuid.uuid4()),
        "user_id": uid,
        "timestamp": ts.isoformat(),
        "is_genuine_user": genuine,
        "impostor_type": impostor_type,
        "ecg_rr_interval_mean": ecg_rr_mean,
        "ecg_rr_interval_std": ecg_rr_std,
        "ecg_qrs_duration_ms": ecg_qrs,
        "ecg_qt_interval_ms": ecg_qt,
        "ecg_p_wave_amplitude": ecg_p,
        "ecg_t_wave_polarity": ecg_t,
        "ecg_cardiac_fingerprint_dist": ecg_dist,
        "ks_dwell_time_mean": ks_dwell,
        "ks_dwell_time_std": ks_dwell_std,
        "ks_flight_time_mean": ks_flight,
        "ks_flight_time_std": ks_flight_std,
        "ks_digraph_latency_mean": ks_digraph,
        "ks_micro_tremor_freq": ks_tremor_f,
        "ks_micro_tremor_amplitude": ks_tremor_a,
        "ks_typing_speed_wpm": ks_wpm,
        "ks_error_rate": ks_err,
        "ks_baseline_cosine_sim": ks_cos,
        "mouse_velocity_mean": mouse_vel,
        "mouse_acceleration_pattern": mouse_accel,
        "mouse_hesitation_count": mouse_hes,
        "mouse_path_linearity": mouse_lin,
        "ecg_match_score": ecg_score,
        "keystroke_match_score": ks_score,
        "behavioral_match_score": beh_score,
        "fused_trust_score": fused,
        "auth_decision": decision,
        "is_legitimate_access": genuine,
        "risk_flags": ",".join(risk_flags) if risk_flags else "NONE",
    }


def main():
    rows = []
    genuine_count = int(NUM_ROWS * 0.8)
    impostor_count = NUM_ROWS - genuine_count

    for _ in range(genuine_count):
        rows.append(gen_row(genuine=True))

    impostor_types = ["CREDENTIAL_THEFT", "DEEPFAKE_BIO", "COERCED_USER"]
    for _ in range(impostor_count):
        rows.append(gen_row(genuine=False, impostor_type=random.choice(impostor_types)))

    random.shuffle(rows)

    os.makedirs("datasets", exist_ok=True)
    with open("datasets/bio_auth_signals.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} rows -> datasets/bio_auth_signals.csv")


if __name__ == "__main__":
    main()
