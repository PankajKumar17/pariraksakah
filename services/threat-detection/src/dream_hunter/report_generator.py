"""
P13 — Dream-State Report Generator
Compiles findings from the night processor, retroactive scanner,
and weak signal amplifier into a comprehensive morning briefing
for the SOC team.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .night_processor import DreamFinding, DreamSession
from .retroactive_scanner import RetroactiveMatch
from .weak_signal_amplifier import AmplifiedSignal

logger = logging.getLogger("cybershield.dream_hunter.report")


@dataclass
class DreamReport:
    report_id: str
    generated_at: str
    session_id: str
    executive_summary: str
    total_findings: int
    critical_findings: int
    missed_threats: List[DreamFinding] = field(default_factory=list)
    retroactive_matches: List[RetroactiveMatch] = field(default_factory=list)
    amplified_signals: List[AmplifiedSignal] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metrics: Dict = field(default_factory=dict)


class ReportGenerator:
    """Generates morning briefing reports from dream-state analysis."""

    def generate(
        self,
        session: DreamSession,
        findings: List[DreamFinding],
        retro_matches: List[RetroactiveMatch],
        amplified: List[AmplifiedSignal],
    ) -> DreamReport:
        """Generate a comprehensive dream report."""
        now = datetime.now(timezone.utc)
        report_id = f"dream-report-{now.strftime('%Y%m%d-%H%M%S')}"

        critical = sum(1 for f in findings if f.severity in ("critical", "high"))
        critical += sum(1 for m in retro_matches if m.severity in ("critical", "high"))
        critical += sum(1 for a in amplified if a.severity in ("critical", "high"))

        total = len(findings) + len(retro_matches) + len(amplified)

        summary = self._generate_summary(session, total, critical, findings, retro_matches, amplified)
        recommendations = self._generate_recommendations(findings, retro_matches, amplified)

        metrics = {
            "events_analyzed": session.events_replayed,
            "dream_findings": len(findings),
            "retroactive_matches": len(retro_matches),
            "amplified_signals": len(amplified),
            "total_findings": total,
            "critical_findings": critical,
            "session_duration": session.completed_at or "in progress",
        }

        report = DreamReport(
            report_id=report_id,
            generated_at=now.isoformat(),
            session_id=session.session_id,
            executive_summary=summary,
            total_findings=total,
            critical_findings=critical,
            missed_threats=[f for f in findings if f.finding_type == "missed_threat"],
            retroactive_matches=retro_matches,
            amplified_signals=amplified,
            recommendations=recommendations,
            metrics=metrics,
        )

        logger.info("Dream report %s generated: %d findings (%d critical)", report_id, total, critical)
        return report

    def _generate_summary(
        self,
        session: DreamSession,
        total: int,
        critical: int,
        findings: List[DreamFinding],
        retro: List[RetroactiveMatch],
        amplified: List[AmplifiedSignal],
    ) -> str:
        lines = [
            f"# CyberShield-X Dream-State Analysis Report",
            f"## Session: {session.session_id}",
            f"",
            f"**Events Replayed:** {session.events_replayed}",
            f"**Total Findings:** {total}",
            f"**Critical/High Findings:** {critical}",
            f"",
        ]

        if critical > 0:
            lines.append("⚠️ **ACTION REQUIRED** — Critical findings detected during overnight analysis.")
        else:
            lines.append("✅ No critical findings. Routine analysis complete.")

        if findings:
            missed = [f for f in findings if f.finding_type == "missed_threat"]
            if missed:
                lines.append(f"\n### Missed Threats: {len(missed)}")
                for f in missed[:5]:
                    lines.append(f"- [{f.severity.upper()}] {f.description} (confidence={f.confidence:.2f})")

        if retro:
            lines.append(f"\n### Retroactive Intelligence Matches: {len(retro)}")
            for m in retro[:5]:
                lines.append(
                    f"- [{m.severity.upper()}] {m.ioc_type}={m.ioc_matched} "
                    f"(source={m.intel_source}, gap={m.detection_gap_hours:.1f}h)"
                )

        if amplified:
            lines.append(f"\n### Amplified Weak Signals: {len(amplified)}")
            for a in amplified[:5]:
                lines.append(f"- [{a.severity.upper()}] {a.description}")

        return "\n".join(lines)

    def _generate_recommendations(
        self,
        findings: List[DreamFinding],
        retro: List[RetroactiveMatch],
        amplified: List[AmplifiedSignal],
    ) -> List[str]:
        recs = set()

        for f in findings:
            if f.recommended_action:
                recs.add(f.recommended_action)
            if f.finding_type == "missed_threat":
                recs.add("Update real-time detection rules based on dream findings")

        for m in retro:
            recs.add(m.recommendation)
            if m.detection_gap_hours > 24:
                recs.add("Improve threat intel feed update frequency")

        for a in amplified:
            if a.severity == "high":
                recs.add("Investigate amplified signal sources for coordinated activity")
            if "distributed" in a.pattern:
                recs.add("Review perimeter defenses for distributed attack patterns")

        return sorted(recs)

    def to_json(self, report: DreamReport) -> str:
        """Serialize report to JSON."""
        return json.dumps({
            "report_id": report.report_id,
            "generated_at": report.generated_at,
            "session_id": report.session_id,
            "executive_summary": report.executive_summary,
            "total_findings": report.total_findings,
            "critical_findings": report.critical_findings,
            "recommendations": report.recommendations,
            "metrics": report.metrics,
        }, indent=2)

    def to_markdown(self, report: DreamReport) -> str:
        """Export report as Markdown."""
        return report.executive_summary
