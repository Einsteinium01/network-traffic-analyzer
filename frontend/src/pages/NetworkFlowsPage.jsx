import React, { useState } from 'react';
import {
  GitBranch,
  Search,
  RefreshCw,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function NetworkFlowsPage() {
  const { flows, isMonitoring, fetchFlows } = useMonitoring();

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
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#121720] border border-[#202735] rounded-xl p-2.5 flex-shrink-0">
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
                  <td colSpan={8} className="py-16 text-center text-[#667085]">
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
