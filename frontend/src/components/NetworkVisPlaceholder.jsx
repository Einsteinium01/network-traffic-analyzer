import React from 'react';
import { Radio, Cpu, Network, Laptop } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function NetworkVisPlaceholder() {
  const { isMonitoring, stats } = useMonitoring();

  const pps = stats.packets_per_second ? stats.packets_per_second.toLocaleString() : '0';
  const bpsVal = stats.bytes_per_second || 0;
  const bps = bpsVal >= 1024 * 1024
    ? `${(bpsVal / (1024 * 1024)).toFixed(2)} MB/s`
    : bpsVal >= 1024
    ? `${(bpsVal / 1024).toFixed(1)} KB/s`
    : `${bpsVal.toFixed(0)} B/s`;
  const activeFlows = stats.active_flows !== undefined ? stats.active_flows.toLocaleString() : '0';

  return (
    <div className="bg-[#121720] border border-[#202735] rounded-[16px] p-4 flex flex-col justify-between relative overflow-hidden h-full min-h-[260px]">
      {/* Card Header */}
      <div className="flex items-center justify-between z-10">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-[#F4F7FB]">Live Network Traffic</h3>
            <span className="px-1.5 py-0.5 text-[9px] font-mono text-[#62E8F7] bg-[#62E8F7]/10 rounded border border-[#62E8F7]/20">
              TOPOLOGY
            </span>
          </div>
          <p className="text-[11px] text-[#667085] mt-0.5">
            Real-time packet distribution and active network flow topology.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[#161B25] border border-[#202735] rounded-full text-[11px] font-mono text-[#62E8F7]">
            <Radio className={`w-3 h-3 ${isMonitoring ? 'animate-pulse text-[#35D07F]' : 'text-[#667085]'}`} />
            <span>{isMonitoring ? 'LIVE LINK' : 'OFFLINE'}</span>
          </div>
        </div>
      </div>

      {/* Central Animated Topology Graph Space */}
      <div className="my-2 relative flex-1 flex items-center justify-center min-h-[160px]">
        {/* Background Grid Accent */}
        <div className="absolute inset-0 bg-[radial-gradient(#202735_1px,transparent_1px)] [background-size:14px_14px] opacity-40 pointer-events-none" />

        {/* Topology Nodes */}
        <div className="relative z-10 w-full max-w-md flex items-center justify-between px-2">
          {/* Internet / Gateway Node */}
          <div className="flex flex-col items-center gap-1.5">
            <div className="w-11 h-11 rounded-xl bg-[#161B25] border border-[#303A4A] flex items-center justify-center text-[#60A5FA] shadow-md">
              <Network className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono font-medium text-[#9AA4B2]">INTERNET</span>
          </div>

          {/* Flow Connection Lines */}
          <div className="flex-1 px-3 relative flex items-center justify-center">
            <div className={`w-full h-[2px] ${isMonitoring ? 'bg-gradient-to-r from-[#60A5FA]/40 via-[#62E8F7]/60 to-[#35D07F]/40' : 'bg-[#202735]'} relative`}>
              {isMonitoring && (
                <div className="absolute top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full bg-[#62E8F7] glow-cyan animate-ping" />
              )}
            </div>
          </div>

          {/* Localhost Target Node */}
          <div className="flex flex-col items-center gap-1.5">
            <div className={`w-13 h-13 rounded-xl bg-[#161B25] border-2 ${isMonitoring ? 'border-[#62E8F7]/40 glow-cyan' : 'border-[#202735]'} flex items-center justify-center text-[#62E8F7]`}>
              <Laptop className="w-6 h-6" />
            </div>
            <span className="text-[10px] font-mono font-semibold text-[#F4F7FB]">LOCALHOST</span>
          </div>

          {/* Connection Line to ML Engine */}
          <div className="flex-1 px-3 relative flex items-center justify-center">
            <div className={`w-full h-[2px] ${isMonitoring ? 'bg-gradient-to-r from-[#35D07F]/40 via-[#A78BFA]/60 to-[#EC5BCB]/40' : 'bg-[#202735]'} relative`}>
              {isMonitoring && (
                <div className="absolute top-1/2 -translate-y-1/2 right-3 w-2.5 h-2.5 rounded-full bg-[#A78BFA] glow-purple animate-pulse" />
              )}
            </div>
          </div>

          {/* ML Detection Engine Node */}
          <div className="flex flex-col items-center gap-1.5">
            <div className={`w-11 h-11 rounded-xl bg-[#161B25] border ${isMonitoring ? 'border-[#A78BFA]/40 glow-purple' : 'border-[#202735]'} flex items-center justify-center text-[#A78BFA]`}>
              <Cpu className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono font-medium text-[#A78BFA]">XGBOOST ML</span>
          </div>
        </div>

        {/* Overlay Stats Card (design.md section 20) */}
        <div className="absolute bottom-1 left-1 bg-[#070B12]/90 border border-[#202735] rounded-lg px-2.5 py-1.5 backdrop-blur-md text-[11px] font-mono flex items-center gap-3">
          <div>
            <div className="text-[9px] text-[#667085] uppercase">Packets/sec</div>
            <div className="font-bold text-[#62E8F7]">{pps}</div>
          </div>
          <div className="h-5 w-[1px] bg-[#202735]" />
          <div>
            <div className="text-[9px] text-[#667085] uppercase">Rate</div>
            <div className="font-bold text-[#F4F7FB]">{bps}</div>
          </div>
          <div className="h-5 w-[1px] bg-[#202735]" />
          <div>
            <div className="text-[9px] text-[#667085] uppercase">Flows</div>
            <div className="font-bold text-[#A78BFA]">{activeFlows}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
