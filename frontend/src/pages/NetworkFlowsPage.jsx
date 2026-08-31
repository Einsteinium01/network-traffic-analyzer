import React, { useState } from 'react';
import {
  GitBranch,
  Search,
  RefreshCw,
  Network,
  Laptop,
  Cpu,
} from 'lucide-react';

import { useMonitoring } from '../context/MonitoringContext';

export default function NetworkFlowsPage() {
  const { flows, stats, isMonitoring, activeInterface, selectedInterface, fetchFlows } = useMonitoring();

  const [searchFilter, setSearchFilter] = useState('');
  const [protoFilter, setProtoFilter] = useState('ALL');

  const cleanSearch = searchFilter.trim().toLowerCase();
  const filteredFlows = flows.filter((f) => {
    if (protoFilter !== 'ALL' && f.protocol !== protoFilter) return false;
    if (cleanSearch) {
      const src = (f.src_ip || '').toLowerCase();
      const dst = (f.dst_ip || '').toLowerCase();
      const id = (f.flow_id || '').toLowerCase();
      const ports = `${f.src_port || ''} ${f.dst_port || ''}`;
      if (!src.includes(cleanSearch) && !dst.includes(cleanSearch) && !id.includes(cleanSearch) && !ports.includes(cleanSearch)) {
        return false;
      }
    }
    return true;
  });

  const totalFlowPkts = flows.reduce((acc, f) => acc + (f.total_packets || 0), 0);
  const totalFlowBytes = flows.reduce((acc, f) => acc + (f.total_bytes || 0), 0);

  const formatBytes = (b) => {
    if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return `${b} B`;
  };

  // Extract unique remote destination endpoints from active flows
  const remoteEndpoints = Array.from(new Set(flows.map((f) => f.dst_ip))).slice(0, 3);
  const pps = stats.packets_per_second ? stats.packets_per_second.toLocaleString() : '0';
  const bytesPerSec = stats.bytes_per_second || 0;
  const trafficRateStr =
    bytesPerSec >= 1024 * 1024
      ? (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s'
      : bytesPerSec >= 1024
      ? (bytesPerSec / 1024).toFixed(1) + ' KB/s'
      : bytesPerSec.toFixed(0) + ' B/s';

  return (
    <div className="h-full flex flex-col space-y-3 max-h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">Network Flows</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#62E8F7]/15 text-[#62E8F7] border border-[#62E8F7]/30 flex items-center gap-1">
              <GitBranch className="w-3 h-3" />
              {flows.length} Active Conversations
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Bi-directional flow aggregations maintained in memory using Welford's incremental online statistics.
          </p>
        </div>

        <button
          onClick={fetchFlows}
          className="px-3 py-1.5 rounded-xl border border-[#202735] bg-[#121720] hover:bg-[#161B25] text-xs font-semibold text-[#9AA4B2] hover:text-[#F4F7FB] flex items-center gap-1.5 transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5 text-[#62E8F7]" />
          <span>REFRESH FLOWS</span>
        </button>
      </div>

      {/* Data-Driven Active Flow Topology Visualization */}
      <div className="bg-[#121720] border border-[#202735] rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden flex-shrink-0">
        <div className="flex items-center justify-between z-10 mb-2">
          <div className="flex items-center gap-2">
            <h3 className="text-xs font-semibold text-[#F4F7FB] flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-[#62E8F7]" />
              Active Flow Topology
            </h3>
            <span className="px-1.5 py-0.2 text-[8px] font-mono text-[#62E8F7] bg-[#62E8F7]/10 rounded border border-[#62E8F7]/20">
              DATA-DRIVEN
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] font-mono">
            <span className="text-[#9AA4B2]">{trafficRateStr}</span>
            <span className="text-[#667085]">|</span>
            <span className="text-[#62E8F7]">{pps} PPS</span>
            <span className="text-[#667085]">|</span>
            <span className="text-[#A78BFA]">{flows.length} Flows</span>
          </div>
        </div>

        {/* Nodes and Flow Lines */}
        <div className="relative py-2 px-4 flex items-center justify-between">
          {/* Remote Endpoints Node */}
          <div className="flex flex-col items-center gap-1 z-10">
            <div className="w-10 h-10 rounded-xl bg-[#161B25] border border-[#303A4A] flex items-center justify-center text-[#60A5FA] shadow-md">
              <Network className="w-4 h-4" />
            </div>
            <span className="text-[9px] font-mono font-medium text-[#9AA4B2]">REMOTE TARGETS</span>
            <div className="text-[8px] font-mono text-[#667085] max-w-[100px] truncate text-center">
              {remoteEndpoints.length > 0 ? remoteEndpoints.join(', ') : 'Internet Gateways'}
            </div>
          </div>

          {/* Connection Line 1 */}
          <div className="flex-1 px-4 relative flex items-center justify-center">
            <div className={`w-full h-[2px] ${isMonitoring ? 'bg-gradient-to-r from-[#60A5FA]/40 via-[#62E8F7]/60 to-[#35D07F]/40' : 'bg-[#202735]'} relative`}>
              {isMonitoring && (
                <div className="absolute top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-[#62E8F7] glow-cyan animate-ping" />
              )}
            </div>
          </div>

          {/* Local Host Node */}
          <div className="flex flex-col items-center gap-1 z-10">
            <div className={`w-11 h-11 rounded-xl bg-[#161B25] border-2 ${isMonitoring ? 'border-[#62E8F7]/40 glow-cyan' : 'border-[#202735]'} flex items-center justify-center text-[#62E8F7]`}>
              <Laptop className="w-5 h-5" />
            </div>
            <span className="text-[9px] font-mono font-semibold text-[#F4F7FB]">LOCALHOST</span>
            <span className="text-[8px] font-mono text-[#62E8F7]">{activeInterface || selectedInterface || 'Auto'}</span>
          </div>

          {/* Connection Line 2 */}
          <div className="flex-1 px-4 relative flex items-center justify-center">
            <div className={`w-full h-[2px] ${isMonitoring ? 'bg-gradient-to-r from-[#35D07F]/40 via-[#A78BFA]/60 to-[#EC5BCB]/40' : 'bg-[#202735]'} relative`}>
              {isMonitoring && (
                <div className="absolute top-1/2 -translate-y-1/2 right-3 w-2 h-2 rounded-full bg-[#A78BFA] glow-purple animate-pulse" />
              )}
            </div>
          </div>

          {/* XGBoost Feature Engine Node */}
          <div className="flex flex-col items-center gap-1 z-10">
            <div className={`w-10 h-10 rounded-xl bg-[#161B25] border ${isMonitoring ? 'border-[#A78BFA]/40 glow-purple' : 'border-[#202735]'} flex items-center justify-center text-[#A78BFA]`}>
              <Cpu className="w-4 h-4" />
            </div>
            <span className="text-[9px] font-mono font-medium text-[#A78BFA]">WELFORD + XGBOOST</span>
            <span className="text-[8px] font-mono text-[#667085]">5.0s Sweep</span>
          </div>
        </div>
      </div>

      {/* Flow KPI Cards (Section 33 of design.md) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 flex-shrink-0">
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3">
          <div className="text-[10px] font-mono uppercase text-[#667085]">Active Flow Table</div>
          <div className="text-2xl font-bold font-mono text-[#62E8F7] mt-0.5">{flows.length}</div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Concurrently tracked sessions</div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3">
          <div className="text-[10px] font-mono uppercase text-[#667085]">Total Aggregated Packets</div>
          <div className="text-2xl font-bold font-mono text-[#F4F7FB] mt-0.5">
            {totalFlowPkts.toLocaleString()}
          </div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Packets in active table</div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3">
          <div className="text-[10px] font-mono uppercase text-[#667085]">Aggregated Volume</div>
          <div className="text-2xl font-bold font-mono text-[#A78BFA] mt-0.5">
            {formatBytes(totalFlowBytes)}
          </div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Payload & header bytes</div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3">
          <div className="text-[10px] font-mono uppercase text-[#667085]">Flow Sampling Policy</div>
          <div className="text-2xl font-bold font-mono text-[#35D07F] mt-0.5">5.0s</div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Periodic XGBoost sweep</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#121720] border border-[#202735] rounded-xl p-2 flex-shrink-0">
        <div className="flex items-center gap-1 text-[11px]">
          <span className="text-[10px] font-mono text-[#667085] uppercase mr-1">Proto:</span>
          {['ALL', 'TCP', 'UDP'].map((proto) => (
            <button
              key={proto}
              onClick={() => setProtoFilter(proto)}
              className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                protoFilter === proto
                  ? 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40'
                  : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>

        <div className="relative w-48 sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#667085] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Filter IP or port..."
            className="w-full bg-[#161B25] border border-[#202735] rounded-lg py-1 pl-8 pr-2.5 text-[11px] text-[#F4F7FB] placeholder-[#667085] focus:outline-none focus:border-[#62E8F7]/40"
          />
        </div>
      </div>

      {/* Flows Table */}
      <div className="flex-1 bg-[#121720] border border-[#202735] rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#161B25] sticky top-0 z-10 text-[10px] uppercase font-mono tracking-wider text-[#667085] border-b border-[#202735]">
              <tr>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Destination Endpoint</th>
                <th className="py-2.5 px-3 text-right">Duration</th>
                <th className="py-2.5 px-3 text-right">Packets (Fwd / Bwd)</th>
                <th className="py-2.5 px-3 text-right">Bytes</th>
                <th className="py-2.5 px-3 text-right">Rate</th>
                <th className="py-2.5 px-3 text-right">Idle Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#202735]/60 text-[11px]">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#667085]">
                    {isMonitoring
                      ? 'No active flows matching filter.'
                      : 'Monitoring is offline. Click "START MONITORING" on the Dashboard to aggregate network flows.'}
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow, idx) => (
                  <tr key={idx} className="hover:bg-[#161B25]/80 transition-colors">
                    <td className="py-2 px-3">
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-[#161B25] border border-[#202735] text-[#60A5FA]">
                        {flow.protocol || 'TCP'}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-[#F4F7FB]">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-2 px-3 font-mono text-[#9AA4B2]">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-2 px-3 font-mono text-right text-[#9AA4B2]">
                      {flow.duration_seconds}s
                    </td>
                    <td className="py-2 px-3 font-mono text-right text-[#F4F7FB]">
                      <span className="font-semibold text-[#62E8F7]">{flow.total_packets}</span>{' '}
                      <span className="text-[10px] text-[#667085]">
                        ({flow.fwd_packets} / {flow.bwd_packets})
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-right text-[#9AA4B2]">
                      {formatBytes(flow.total_bytes)}
                    </td>
                    <td className="py-2 px-3 font-mono text-right text-[#A78BFA]">
                      {flow.packets_per_second} pps
                    </td>
                    <td className="py-2 px-3 font-mono text-right text-[#667085]">
                      {flow.idle_seconds}s
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
