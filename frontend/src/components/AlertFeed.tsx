import React from 'react';
import type { Alert } from '../store/useAppStore';

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
};

interface AlertFeedProps {
  alerts: Alert[];
}

export default function AlertFeed({ alerts }: AlertFeedProps) {
  if (alerts.length === 0) {
    return <p className="text-gray-500 text-sm">No alerts</p>;
  }

  return (
    <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className="flex items-start gap-3 p-2.5 bg-[#0F172A] rounded-lg hover:bg-[#0F172A]/70 transition-colors"
        >
          <div className="mt-0.5">
            <span className={`badge ${SEVERITY_BADGE[alert.severity]}`}>
              {alert.severity}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-200 truncate">
                {alert.type}
              </span>
              {alert.mitre_technique && (
                <span className="text-xs text-[#6C63FF] bg-[#6C63FF]/10 px-1.5 py-0.5 rounded">
                  {alert.mitre_technique}
                </span>
              )}
            </div>
            <p className="text-xs text-gray-400 truncate mt-0.5">
              {alert.description}
            </p>
            <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
              <span className="font-mono">{alert.source_ip}</span>
              <span>
                {new Date(alert.timestamp).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })}
              </span>
            </div>
          </div>
          <div>
            <span
              className={`w-2 h-2 rounded-full inline-block ${
                alert.status === 'open'
                  ? 'bg-red-500'
                  : alert.status === 'investigating'
                  ? 'bg-yellow-500'
                  : 'bg-green-500'
              }`}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
