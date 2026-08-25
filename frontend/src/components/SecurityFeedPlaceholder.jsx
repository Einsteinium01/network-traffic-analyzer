import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2, Play } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function SecurityFeedPlaceholder() {
  const { securityEvents } = useMonitoring();

  const iconMap = {
    attack: ShieldAlert,
    warning: AlertTriangle,
    normal: CheckCircle2,
  };

  const typeColors = {
    attack: { text: 'text-[#FF5C6C]', dot: 'bg-[#FF5C6C]', bg: 'bg-[#FF5C6C]/10 border-[#FF5C6C]/20' },
    warning: { text: 'text-[#F5B84B]', dot: 'bg-[#F5B84B]', bg: 'bg-[#F5B84B]/10 border-[#F5B84B]/20' },
    normal: { text: 'text-[#62E8F7]', dot: 'bg-[#62E8F7]', bg: 'bg-[#62E8F7]/10 border-[#62E8F7]/20' },
  };

  const displayEvents = securityEvents.length > 0 ? securityEvents.slice(0, 4) : [];

  return (
    <div className="bg-[#121720] border border-[#202735] rounded-[16px] p-4 flex flex-col justify-between h-full min-h-[260px] overflow-hidden">
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[#F4F7FB]">Security Events</h3>
          <span className="text-[9px] font-mono uppercase text-[#667085]">LIVE FEED</span>
        </div>

        {/* Timeline */}
        <div className="relative pl-3.5 space-y-2.5 before:absolute before:left-[5px] before:top-2 before:bottom-2 before:w-[2px] before:bg-[#202735]">
          {displayEvents.map((evt) => {
            const Icon = iconMap[evt.type] || Play;
            const style = typeColors[evt.type] || typeColors.normal;
            return (
              <div key={evt.id} className="relative flex items-start gap-2.5 group">
                {/* Timeline Dot */}
                <div
                  className={`w-2.5 h-2.5 rounded-full border-2 border-[#121720] ${style.dot} absolute -left-[16px] top-1 z-10`}
                />

                <div className="flex-1 bg-[#161B25] border border-[#202735] group-hover:border-[#303A4A] rounded-lg px-2.5 py-1.5 transition-all">
                  <div className="flex items-center justify-between">
                    <div className={`text-[11px] font-semibold flex items-center gap-1 ${style.text}`}>
                      <Icon className="w-3 h-3" />
                      <span className="truncate max-w-[140px]">{evt.title}</span>
                    </div>
                    <span className="text-[9px] text-[#667085] font-mono">{evt.time}</span>
                  </div>
                  <p className="text-[10px] text-[#9AA4B2] mt-0.5 leading-snug line-clamp-1">{evt.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
