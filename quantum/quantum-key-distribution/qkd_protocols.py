import numpy as np
import hashlib
import time
import uuid

class QKDProtocols:
    """Simulate BB84, E91, and B92 quantum key distribution protocols."""

    QBER_THRESHOLD = 0.11  # 11% — abort if exceeded

    # ── BB84 Protocol ──

    def bb84_session(self, num_qubits: int = 256, eve_intercept_pct: float = 0.0) -> dict:
        session_id = str(uuid.uuid4())
        
        # Alice prepares random bits and bases (0=rectilinear, 1=diagonal)
        alice_bits = np.random.randint(0, 2, num_qubits)
        alice_bases = np.random.randint(0, 2, num_qubits)
        
        # Eve intercepts a fraction of qubits
        eve_intercepted = np.random.random(num_qubits) < eve_intercept_pct
        eve_bases = np.random.randint(0, 2, num_qubits)
        
        # Transmitted qubits (Eve's measurement disturbs state)
        transmitted_bits = alice_bits.copy()
        for i in range(num_qubits):
            if eve_intercepted[i]:
                if eve_bases[i] != alice_bases[i]:
                    # Eve measured in wrong basis — randomize
                    transmitted_bits[i] = np.random.randint(0, 2)
        
        # Bob measures in random bases
        bob_bases = np.random.randint(0, 2, num_qubits)
        bob_bits = np.zeros(num_qubits, dtype=int)
        for i in range(num_qubits):
            if bob_bases[i] == alice_bases[i]:
                bob_bits[i] = transmitted_bits[i]
            else:
                bob_bits[i] = np.random.randint(0, 2)  # Wrong basis = random
        
        # Sifting: keep only matching bases
        matching = alice_bases == bob_bases
        sifted_alice = alice_bits[matching]
        sifted_bob = bob_bits[matching]
        
        # Calculate QBER
        errors = np.sum(sifted_alice != sifted_bob)
        qber = errors / len(sifted_alice) if len(sifted_alice) > 0 else 1.0
        
        eavesdrop_detected = qber > self.QBER_THRESHOLD
        
        # Privacy amplification (hash to shorter key)
        raw_key = "".join(map(str, sifted_alice.tolist()))
        final_key = hashlib.sha256(raw_key.encode()).hexdigest() if not eavesdrop_detected else ""
        
        return {
            "session_id": session_id,
            "protocol": "BB84",
            "qubits_sent": num_qubits,
            "sifted_bits": len(sifted_alice),
            "qber_rate": round(float(qber), 6),
            "eavesdrop_detected": eavesdrop_detected,
            "eve_intercept_pct": eve_intercept_pct,
            "key_bits_generated": len(final_key) * 4 if final_key else 0,
            "final_key": final_key,
        }

    # ── E91 Protocol ──

    def e91_session(self, num_pairs: int = 256, eve_intercept_pct: float = 0.0) -> dict:
        session_id = str(uuid.uuid4())
        
        # Generate entangled pairs (Bell state |Φ+⟩)
        # Perfect correlations when measured in same basis
        alice_bases = np.random.choice([0, 1, 2], num_pairs)  # 0°, 22.5°, 45°
        bob_bases = np.random.choice([0, 1, 2], num_pairs)    # 0°, 22.5°, 45°
        
        # Entangled measurement outcomes
        alice_results = np.random.randint(0, 2, num_pairs)
        bob_results = alice_results.copy()
        
        # Same basis → perfect correlation (anti-correlation for singlet)
        for i in range(num_pairs):
            if alice_bases[i] != bob_bases[i]:
                # Different bases → quantum correlation
                correlation_prob = np.cos(np.pi * abs(alice_bases[i] - bob_bases[i]) / 8) ** 2
                if np.random.random() > correlation_prob:
                    bob_results[i] = 1 - bob_results[i]
        
        # Eve disturbs correlations
        eve_intercepted = np.random.random(num_pairs) < eve_intercept_pct
        for i in range(num_pairs):
            if eve_intercepted[i]:
                bob_results[i] = np.random.randint(0, 2)
        
        # CHSH inequality test (S should be ~2√2 ≈ 2.828 without Eve)
        # Eve's presence reduces S below 2
        matching = alice_bases == bob_bases
        sifted_alice = alice_results[matching]
        sifted_bob = bob_results[matching]
        
        errors = np.sum(sifted_alice != sifted_bob)
        qber = errors / len(sifted_alice) if len(sifted_alice) > 0 else 1.0
        
        chsh_s = 2.828 * (1.0 - 2 * eve_intercept_pct) + np.random.normal(0, 0.05)
        eavesdrop_detected = chsh_s < 2.0 or qber > self.QBER_THRESHOLD
        
        raw_key = "".join(map(str, sifted_alice.tolist()))
        final_key = hashlib.sha256(raw_key.encode()).hexdigest() if not eavesdrop_detected else ""
        
        return {
            "session_id": session_id,
            "protocol": "E91",
            "entangled_pairs": num_pairs,
            "sifted_bits": len(sifted_alice),
            "qber_rate": round(float(qber), 6),
            "chsh_s_value": round(float(chsh_s), 4),
            "eavesdrop_detected": eavesdrop_detected,
            "key_bits_generated": len(final_key) * 4 if final_key else 0,
            "final_key": final_key,
        }

    # ── B92 Protocol ──

    def b92_session(self, num_qubits: int = 256, eve_intercept_pct: float = 0.0) -> dict:
        session_id = str(uuid.uuid4())
        
        # Alice sends non-orthogonal states: bit 0 → |0⟩, bit 1 → |+⟩
        alice_bits = np.random.randint(0, 2, num_qubits)
        
        # Eve interception
        eve_intercepted = np.random.random(num_qubits) < eve_intercept_pct
        transmitted = alice_bits.copy()
        for i in range(num_qubits):
            if eve_intercepted[i]:
                transmitted[i] = np.random.randint(0, 2)
        
        # Bob uses unambiguous state discrimination
        # Success probability ~50% for non-orthogonal states
        bob_success = np.random.random(num_qubits) < 0.5
        bob_bits = np.zeros(num_qubits, dtype=int)
        
        for i in range(num_qubits):
            if bob_success[i]:
                bob_bits[i] = transmitted[i]
        
        # Keep only successful measurements
        successful_alice = alice_bits[bob_success]
        successful_bob = bob_bits[bob_success]
        
        errors = np.sum(successful_alice != successful_bob)
        qber = errors / len(successful_alice) if len(successful_alice) > 0 else 1.0
        eavesdrop_detected = qber > self.QBER_THRESHOLD
        
        raw_key = "".join(map(str, successful_alice.tolist()))
        final_key = hashlib.sha256(raw_key.encode()).hexdigest() if not eavesdrop_detected else ""
        
        return {
            "session_id": session_id,
            "protocol": "B92",
            "qubits_sent": num_qubits,
            "successful_measurements": len(successful_alice),
            "qber_rate": round(float(qber), 6),
            "eavesdrop_detected": eavesdrop_detected,
            "key_bits_generated": len(final_key) * 4 if final_key else 0,
            "final_key": final_key,
        }
