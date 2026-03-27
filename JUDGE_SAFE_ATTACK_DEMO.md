# Judge Safe Attack Demo (Local Only)

Use this flow to demonstrate security outcomes without attacking any real system.

## 1. Start platform

```bash
docker compose up -d --build
```

Verify:

- Dashboard: `http://localhost:3000`
- Gateway health: `http://localhost:8080/health`
- Gateway readiness: `http://localhost:8080/ready`

## 2. Run one-command judge demo

From repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JudgeSafeDemo.ps1
```

What this script proves:

1. Protected routes reject unauthorized access.
2. Invalid JWT tokens are rejected.
3. Threat-wave simulation triggers detection signals.
4. Anonymous phishing simulation escalates into incident response.
5. Incident response creates playbook activity and audit evidence.
6. Optional controlled request burst shows rate limiting (HTTP 429).

## 3. Optional extended version

Include malware and ransomware injectors:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JudgeSafeDemo.ps1 -IncludeExtendedScenarios
```

Skip the rate-limit burst:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JudgeSafeDemo.ps1 -SkipRateLimitDemo
```

## 4. Suggested narration (about 2 minutes)

1. "We are running a local, controlled simulation only."
2. "First, we verify hard controls: unauthorized and invalid-token requests are blocked."
3. "Now we inject threat telemetry and watch detections update in real time."
4. "Next, we simulate a social-engineering campaign and show automated escalation."
5. "Finally, we trigger incident response and verify auditability."
6. "This demonstrates detection, prevention, and response as one system."

## 5. Important safety note

Only run this in your local demo environment with synthetic data. Do not target production or third-party systems.

