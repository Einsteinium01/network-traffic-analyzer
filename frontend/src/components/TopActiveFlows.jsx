import React from 'react';
import { GitBranch, ArrowRight } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function TopActiveFlows() {
  const { flows, isMonitoring } = useMonitoring();

  // Sort flows by total_packets to find top active conversations
  const sortedFlows = [...flows]
    .sort((a, b) => (b.total_packets || 0) - (a.total_packets || 0))
    .slice(0, 3);

  const formatBytes = (b) => {
    if (!b) return '0 B';
    if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return `${b} B`;
  };

  return (
    <div className="bg-[#121720] border border-[#202735] rounded-[14px] p-2.5 flex flex-col justify-between flex-shrink-0">
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-1.5">
          <GitBranch className="w-3.5 h-3.5 text-[#62E8F7]" />
          <h4 className="text-xs font-semibold text-[#F4F7FB]">Top Active Flows</h4>
        </div>
        <span className="text-[9px] font-mono text-[#667085] uppercase">
          {flows.length} SESSIONS MONITORED
        </span>
      </div>

      {sortedFlows.length === 0 ? (
        <div className="py-2 text-center text-[10px] text-[#667085] font-mono">
          {isMonitoring ? 'Aggregating active flow conversations...' : 'Engine idle — no active flows'}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {sortedFlows.map((flow, idx) => (
            <div
              key={flow.flow_id || idx}
              className="bg-[#161B25] border border-[#202735] rounded-lg p-2 flex flex-col justify-between text-[10px]"
            >
              <div className="flex items-center justify-between font-mono mb-0.5">
                <span className="px-1 py-0.2 rounded text-[8px] font-semibold bg-[#62E8F7]/10 text-[#62E8F7] border border-[#62E8F7]/20">
                  {flow.protocol || 'TCP'}
                </span>
                <span className="text-[#667085] text-[9px]">{flow.duration_seconds || 0}s</span>
              </div>

              <div className="flex items-center gap-1 font-mono text-[#F4F7FB] truncate my-0.5 text-[10px]">
                <span className="truncate max-w-[65px] text-[#9AA4B2]">{flow.src_ip}</span>
                <ArrowRight className="w-2.5 h-2.5 text-[#667085] flex-shrink-0" />
                <span className="truncate max-w-[65px] text-[#62E8F7]">{flow.dst_ip}</span>
                <span className="text-[#667085]">:{flow.dst_port}</span>
              </div>

              <div className="flex items-center justify-between text-[#9AA4B2] pt-1 border-t border-[#202735]/60 font-mono text-[9px]">
                <span>{flow.total_packets || 0} pkts</span>
                <span className="text-[#A78BFA]">{formatBytes(flow.total_bytes)}</span>
                <span className="text-[#35D07F]">{flow.packets_per_second || 0} pps</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
