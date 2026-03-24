"""Repository pattern for database access - threat and event queries."""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_
import logging

from .models import ThreatEvent, NetworkEvent, UEBAEvent, AlertSuppression

logger = logging.getLogger("threat-detection.repository")


class ThreatRepository:
    """Repository for ThreatEvent queries and mutations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_threat(self, threat_dict: Dict[str, Any]) -> ThreatEvent:
        """Store a detected threat to database."""
        threat = ThreatEvent(**threat_dict)
        self.session.add(threat)
        self.session.commit()
        logger.info(f"Stored threat {threat.id} ({threat.severity}/{threat.threat_type})")
        return threat
    
    def get_threat_by_id(self, threat_id: str) -> Optional[ThreatEvent]:
        """Retrieve threat by ID."""
        return self.session.query(ThreatEvent).filter(ThreatEvent.id == threat_id).first()
    
    def get_recent_threats(
        self, 
        limit: int = 50, 
        severity: Optional[str] = None,
        hours_back: int = 24
    ) -> List[ThreatEvent]:
        """Get recent threats with optional severity filter."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        query = self.session.query(ThreatEvent).filter(
            ThreatEvent.detected_at >= cutoff_time
        )
        
        if severity:
            query = query.filter(ThreatEvent.severity == severity)
        
        return query.order_by(desc(ThreatEvent.detected_at)).limit(limit).all()
    
    def get_threats_by_ip(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 100
    ) -> List[ThreatEvent]:
        """Get threats involving specific IP addresses."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        filters = [ThreatEvent.detected_at >= cutoff_time]
        
        if src_ip:
            filters.append(ThreatEvent.src_ip == src_ip)
        if dst_ip:
            filters.append(ThreatEvent.dst_ip == dst_ip)
        
        if not src_ip and not dst_ip:
            return []
        
        query = self.session.query(ThreatEvent).filter(and_(*filters))
        return query.order_by(desc(ThreatEvent.detected_at)).limit(limit).all()
    
    def get_threats_by_user(
        self,
        user_id: str,
        hours_back: int = 24,
        limit: int = 100
    ) -> List[ThreatEvent]:
        """Get threats associated with a user."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        return self.session.query(ThreatEvent).filter(
            and_(
                ThreatEvent.user_id == user_id,
                ThreatEvent.detected_at >= cutoff_time
            )
        ).order_by(desc(ThreatEvent.detected_at)).limit(limit).all()
    
    def get_threats_by_technique(
        self,
        mitre_technique: str,
        hours_back: int = 24,
        limit: int = 100
    ) -> List[ThreatEvent]:
        """Get threats by MITRE technique."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        return self.session.query(ThreatEvent).filter(
            and_(
                ThreatEvent.mitre_technique == mitre_technique,
                ThreatEvent.detected_at >= cutoff_time
            )
        ).order_by(desc(ThreatEvent.detected_at)).limit(limit).all()
    
    def get_threat_statistics(self, hours_back: int = 24) -> Dict[str, Any]:
        """Get threat statistics for dashboard."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Total threats
        total_count = self.session.query(ThreatEvent).filter(
            ThreatEvent.detected_at >= cutoff_time
        ).count()
        
        # By severity
        severity_counts = {}
        for severity in ["critical", "high", "medium", "low"]:
            count = self.session.query(ThreatEvent).filter(
                and_(
                    ThreatEvent.detected_at >= cutoff_time,
                    ThreatEvent.severity == severity
                )
            ).count()
            severity_counts[severity] = count
        
        # By threat type
        threats = self.session.query(ThreatEvent).filter(
            ThreatEvent.detected_at >= cutoff_time
        ).all()
        
        type_counts = {}
        for threat in threats:
            threat_type = threat.threat_type or "unknown"
            type_counts[threat_type] = type_counts.get(threat_type, 0) + 1
        
        # Top attackers
        top_src_ips = {}
        for threat in threats:
            if threat.src_ip:
                top_src_ips[threat.src_ip] = top_src_ips.get(threat.src_ip, 0) + 1
        
        top_src_ips = sorted(top_src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_threats": total_count,
            "by_severity": severity_counts,
            "by_threat_type": type_counts,
            "top_source_ips": top_src_ips,
        }
    
    def update_threat_status(self, threat_id: str, status: str, note: Optional[str] = None) -> Optional[ThreatEvent]:
        """Update threat status (open, investigating, resolved, false_positive)."""
        threat = self.get_threat_by_id(threat_id)
        if not threat:
            return None
        
        threat.status = status
        if note:
            threat.analyst_note = note
        
        self.session.commit()
        logger.info(f"Updated threat {threat_id} status to {status}")
        return threat


class NetworkEventRepository:
    """Repository for NetworkEvent queries and mutations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_event(self, event_dict: Dict[str, Any]) -> NetworkEvent:
        """Store a raw network event."""
        event = NetworkEvent(**event_dict)
        self.session.add(event)
        self.session.commit()
        return event
    
    def get_events_by_flow(
        self,
        src_ip: str,
        dst_ip: str,
        hours_back: int = 24,
        limit: int = 1000
    ) -> List[NetworkEvent]:
        """Get all events in a network flow."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        return self.session.query(NetworkEvent).filter(
            and_(
                NetworkEvent.event_time >= cutoff_time,
                NetworkEvent.src_ip == src_ip,
                NetworkEvent.dst_ip == dst_ip
            )
        ).order_by(desc(NetworkEvent.event_time)).limit(limit).all()


class UEBAEventRepository:
    """Repository for UEBAEvent queries and mutations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_event(self, event_dict: Dict[str, Any]) -> UEBAEvent:
        """Store a UEBA event."""
        event = UEBAEvent(**event_dict)
        self.session.add(event)
        self.session.commit()
        return event
    
    def get_user_baseline(
        self,
        user_id: str,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get user behavior baseline."""
        cutoff_time = datetime.utcnow() - timedelta(days=days_back)
        
        events = self.session.query(UEBAEvent).filter(
            and_(
                UEBAEvent.user_id == user_id,
                UEBAEvent.event_time >= cutoff_time
            )
        ).all()
        
        if not events:
            return {
                "user_id": user_id,
                "event_count": 0,
                "threat_count": 0,
                "avg_anomaly_score": 0.0,
            }
        
        threat_count = sum(1 for e in events if e.threat_detected)
        avg_anomaly = sum(e.anomaly_score for e in events) / len(events)
        
        return {
            "user_id": user_id,
            "event_count": len(events),
            "threat_count": threat_count,
            "avg_anomaly_score": avg_anomaly,
            "first_event": events[0].event_time if events else None,
            "last_event": events[-1].event_time if events else None,
        }


class SuppressionRepository:
    """Repository for alert suppression management."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_suppression(self, suppression_dict: Dict[str, Any]) -> AlertSuppression:
        """Create a new suppression rule."""
        suppression = AlertSuppression(**suppression_dict)
        self.session.add(suppression)
        self.session.commit()
        logger.info(f"Created suppression {suppression.id}: {suppression.reason}")
        return suppression
    
    def is_suppressed(self, threat_pattern_hash: str) -> bool:
        """Check if a threat pattern is currently suppressed."""
        now = datetime.utcnow()
        
        suppression = self.session.query(AlertSuppression).filter(
            and_(
                AlertSuppression.threat_pattern_hash == threat_pattern_hash,
                AlertSuppression.suppression_until > now
            )
        ).first()
        
        return suppression is not None
    
    def increment_suppression_count(self, threat_pattern_hash: str) -> None:
        """Increment count of suppressed alerts for a pattern."""
        now = datetime.utcnow()
        
        suppression = self.session.query(AlertSuppression).filter(
            and_(
                AlertSuppression.threat_pattern_hash == threat_pattern_hash,
                AlertSuppression.suppression_until > now
            )
        ).first()
        
        if suppression:
            suppression.count_suppressed += 1
            self.session.commit()
