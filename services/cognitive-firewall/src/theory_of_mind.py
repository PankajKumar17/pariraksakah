"""
P12 — Theory of Mind Engine
Hidden Markov Model (HMM) that predicts attacker intent by modelling
their cognitive state transitions: reconnaissance → exploitation →
persistence → exfiltration.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("cybershield.cognitive.theory_of_mind")


# ── Attacker cognitive states ───────────────────

STATES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_control",
    "actions_on_objective",
]

# Observable event types that map to hidden states
OBSERVATIONS = [
    "port_scan",
    "vulnerability_scan",
    "phishing_email",
    "exploit_attempt",
    "malware_download",
    "lateral_movement",
    "privilege_escalation",
    "data_access",
    "c2_beacon",
    "data_exfiltration",
    "ransomware_execution",
]


@dataclass
class IntentPrediction:
    current_state: str
    state_probabilities: Dict[str, float]
    predicted_next_state: str
    predicted_next_actions: List[str]
    urgency_score: float           # 0-1, higher = more urgent
    confidence: float


class AttackerHMM:
    """Hidden Markov Model for attacker intent prediction.

    Hidden states: Kill chain stages
    Observations: Security event types
    """

    def __init__(self):
        self.n_states = len(STATES)
        self.n_obs = len(OBSERVATIONS)

        # Transition matrix A[i][j] = P(state_j | state_i)
        self.A = self._init_transition_matrix()
        # Emission matrix B[i][k] = P(obs_k | state_i)
        self.B = self._init_emission_matrix()
        # Initial state distribution
        self.pi = np.zeros(self.n_states)
        self.pi[0] = 0.7   # Most attacks start at reconnaissance
        self.pi[1] = 0.15
        self.pi[2] = 0.1
        self.pi[3] = 0.05

        # State-to-index mappings
        self.state2idx = {s: i for i, s in enumerate(STATES)}
        self.obs2idx = {o: i for i, o in enumerate(OBSERVATIONS)}

    def _init_transition_matrix(self) -> np.ndarray:
        """Kill chain progression probabilities."""
        A = np.zeros((self.n_states, self.n_states))
        # Attackers generally progress forward in the kill chain
        for i in range(self.n_states):
            A[i, i] = 0.3  # Stay in current state
            if i + 1 < self.n_states:
                A[i, i + 1] = 0.5  # Progress to next stage
            if i + 2 < self.n_states:
                A[i, i + 2] = 0.1  # Skip a stage
            if i > 0:
                A[i, i - 1] = 0.1  # Retreat (e.g., re-reconnaissance)
        # Normalize rows
        for i in range(self.n_states):
            A[i] /= A[i].sum() + 1e-10
        return A

    def _init_emission_matrix(self) -> np.ndarray:
        """Which events are likely in each kill chain stage."""
        B = np.ones((self.n_states, self.n_obs)) * 0.01  # Small base probability

        # reconnaissance → port_scan, vuln_scan
        B[0, 0] = 0.4; B[0, 1] = 0.4
        # weaponization → (mostly unobservable, low emission)
        B[1, 2] = 0.3; B[1, 3] = 0.2
        # delivery → phishing, exploit
        B[2, 2] = 0.5; B[2, 3] = 0.2
        # exploitation → exploit, malware_download
        B[3, 3] = 0.4; B[3, 4] = 0.3
        # installation → malware_download, privilege_escalation
        B[4, 4] = 0.3; B[4, 6] = 0.3
        # command_control → c2_beacon, lateral_movement
        B[5, 5] = 0.3; B[5, 8] = 0.4
        # actions_on_objective → data_access, exfil, ransomware
        B[6, 7] = 0.3; B[6, 9] = 0.3; B[6, 10] = 0.2

        # Normalize rows
        for i in range(self.n_states):
            B[i] /= B[i].sum()
        return B

    def forward(self, observations: List[str]) -> np.ndarray:
        """Forward algorithm: compute P(state | observations)."""
        T = len(observations)
        alpha = np.zeros((T, self.n_states))

        # Initialize
        obs_idx = self.obs2idx.get(observations[0], 0)
        alpha[0] = self.pi * self.B[:, obs_idx]
        alpha[0] /= alpha[0].sum() + 1e-10

        # Forward pass
        for t in range(1, T):
            obs_idx = self.obs2idx.get(observations[t], 0)
            for j in range(self.n_states):
                alpha[t, j] = np.sum(alpha[t - 1] * self.A[:, j]) * self.B[j, obs_idx]
            alpha[t] /= alpha[t].sum() + 1e-10

        return alpha

    def viterbi(self, observations: List[str]) -> List[str]:
        """Viterbi algorithm: find most likely state sequence."""
        T = len(observations)
        delta = np.zeros((T, self.n_states))
        psi = np.zeros((T, self.n_states), dtype=int)

        obs_idx = self.obs2idx.get(observations[0], 0)
        delta[0] = np.log(self.pi + 1e-10) + np.log(self.B[:, obs_idx] + 1e-10)

        for t in range(1, T):
            obs_idx = self.obs2idx.get(observations[t], 0)
            for j in range(self.n_states):
                candidates = delta[t - 1] + np.log(self.A[:, j] + 1e-10)
                psi[t, j] = int(np.argmax(candidates))
                delta[t, j] = candidates[psi[t, j]] + np.log(self.B[j, obs_idx] + 1e-10)

        # Backtrack
        path = [0] * T
        path[-1] = int(np.argmax(delta[-1]))
        for t in range(T - 2, -1, -1):
            path[t] = psi[t + 1, path[t + 1]]

        return [STATES[s] for s in path]

    def predict_intent(self, observation_sequence: List[str]) -> IntentPrediction:
        """Predict attacker intent from a sequence of observed events."""
        if not observation_sequence:
            return IntentPrediction(
                current_state="unknown",
                state_probabilities={},
                predicted_next_state="reconnaissance",
                predicted_next_actions=[],
                urgency_score=0.0,
                confidence=0.0,
            )

        # Run forward algorithm
        alpha = self.forward(observation_sequence)
        current_probs = alpha[-1]

        # Current most likely state
        current_idx = int(np.argmax(current_probs))
        current_state = STATES[current_idx]

        # Predict next state
        next_probs = self.A[current_idx]
        next_idx = int(np.argmax(next_probs))
        next_state = STATES[next_idx]

        # Predict likely next observations
        next_actions = []
        top_obs_idx = np.argsort(self.B[next_idx])[::-1][:3]
        for idx in top_obs_idx:
            if self.B[next_idx, idx] > 0.05:
                next_actions.append(OBSERVATIONS[idx])

        # Urgency: later kill chain stages = more urgent
        urgency = current_idx / (self.n_states - 1)

        # Confidence from state probability concentration
        confidence = float(current_probs[current_idx])

        state_probs = {STATES[i]: float(current_probs[i]) for i in range(self.n_states)}

        return IntentPrediction(
            current_state=current_state,
            state_probabilities=state_probs,
            predicted_next_state=next_state,
            predicted_next_actions=next_actions,
            urgency_score=float(urgency),
            confidence=confidence,
        )

    def update_model(self, observation_sequences: List[List[str]], n_iter: int = 10):
        """Baum-Welch EM algorithm for model parameter re-estimation."""
        for iteration in range(n_iter):
            A_num = np.zeros_like(self.A)
            B_num = np.zeros_like(self.B)
            pi_num = np.zeros_like(self.pi)

            for obs_seq in observation_sequences:
                if len(obs_seq) < 2:
                    continue
                T = len(obs_seq)
                alpha = self.forward(obs_seq)

                # Backward pass
                beta = np.zeros((T, self.n_states))
                beta[-1] = 1.0
                for t in range(T - 2, -1, -1):
                    obs_idx = self.obs2idx.get(obs_seq[t + 1], 0)
                    for i in range(self.n_states):
                        beta[t, i] = np.sum(self.A[i] * self.B[:, obs_idx] * beta[t + 1])
                    beta[t] /= beta[t].sum() + 1e-10

                # Gamma and Xi
                gamma = alpha * beta
                gamma /= gamma.sum(axis=1, keepdims=True) + 1e-10

                pi_num += gamma[0]

                for t in range(T - 1):
                    obs_idx = self.obs2idx.get(obs_seq[t + 1], 0)
                    for i in range(self.n_states):
                        for j in range(self.n_states):
                            A_num[i, j] += (
                                alpha[t, i] * self.A[i, j] *
                                self.B[j, obs_idx] * beta[t + 1, j]
                            )

                for t in range(T):
                    obs_idx = self.obs2idx.get(obs_seq[t], 0)
                    B_num[:, obs_idx] += gamma[t]

            # M-step: update parameters
            for i in range(self.n_states):
                row_sum = A_num[i].sum()
                if row_sum > 0:
                    self.A[i] = A_num[i] / row_sum

                obs_sum = B_num[i].sum()
                if obs_sum > 0:
                    self.B[i] = B_num[i] / obs_sum

            pi_sum = pi_num.sum()
            if pi_sum > 0:
                self.pi = pi_num / pi_sum

            logger.debug("Baum-Welch iteration %d complete", iteration + 1)
