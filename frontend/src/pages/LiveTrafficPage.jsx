import React, { useState, useEffect } from 'react';
import {
  Pause,
  Play,
  Search,
  Zap,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';

import { useMonitoring } from '../context/MonitoringContext';

export default function LiveTrafficPage() {
  const { isMonitoring, stats, recentPackets, selectedInterface, activeInterface, activeMode } =
    useMonitoring();

  const [isPaused, setIsPaused] = useState(false);
  const [displayPackets, setDisplayPackets] = useState([]);
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [predictionFilter, setPredictionFilter] = useState('ALL');
  const [searchFilter, setSearchFilter] = useState('');
  const [rateHistory, setRateHistory] = useState([]);

  useEffect(() => {
    if (!isPaused) {
      setDisplayPackets(recentPackets);
    }
  }, [recentPackets, isPaused]);

  useEffect(() => {
    const pps = stats.packets_per_second || 0;
    const bps = stats.bytes_per_second || 0;
    setRateHistory((prev) => {
      const next = [...prev, { pps, bps, time: Date.now() }];
      return next.slice(-30);
    });
  }, [stats.packets_per_second, stats.bytes_per_second]);

  const cleanSearch = searchFilter.trim().toLowerCase();
  const filteredPackets = displayPackets.filter((p) => {
    if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) return false;
    if (predictionFilter === 'BENIGN' && p.is_attack) return false;
    if (predictionFilter === 'ATTACK' && !p.is_attack) return false;
    if (cleanSearch) {
      const src = (p.src_ip || '').toLowerCase();
      const dst = (p.dst_ip || '').toLowerCase();
      const proto = (p.protocol || '').toLowerCase();
      const port = `${p.src_port || ''} ${p.dst_port || ''}`;
      if (
        !src.includes(cleanSearch) &&
        !dst.includes(cleanSearch) &&
        !proto.includes(cleanSearch) &&
        !port.includes(cleanSearch)
      ) {
        return false;
      }
    }
    return true;
  });

  const bytesPerSec = stats.bytes_per_second || 0;
  const trafficRateStr =
    bytesPerSec >= 1024 * 1024
      ? (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s'
      : bytesPerSec >= 1024
      ? (bytesPerSec / 1024).toFixed(1) + ' KB/s'
      : bytesPerSec.toFixed(0) + ' B/s';

  const maxPps = Math.max(...rateHistory.map((r) => r.pps), 10);
  const chartPoints = rateHistory
    .map((r, idx) => {
      const x = (idx / Math.max(rateHistory.length - 1, 1)) * 300;
      const y = 45 - (r.pps / maxPps) * 35;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <div className="h-full flex flex-col space-y-3 max-h-full overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">Live Traffic Stream</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#62E8F7]/15 text-[#62E8F7] border border-[#62E8F7]/30 flex items-center gap-1">
              <Zap className="w-3 h-3" />
              {isMonitoring
                ? `${activeMode}: ${activeInterface || selectedInterface || 'Auto'}`
                : 'CAPTURE OFFLINE'}
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Microsecond packet stream captured via Direct Npcap with real-time classification.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
              isPaused
                ? 'bg-[#FFC043]/20 border-[#FFC043]/40 text-[#FFC043]'
                : 'bg-[#121720] border-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB]'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'RESUME STREAM' : 'PAUSE STREAM'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Banner + Real-time Rate Chart */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 flex-shrink-0">
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[10px] uppercase font-mono text-[#667085]">Live Capture Rate</div>
          <div className="text-2xl font-bold font-mono text-[#62E8F7] mt-1">
            {stats.packets_per_second ? stats.packets_per_second.toLocaleString() : '0'}{' '}
            <span className="text-xs text-[#9AA4B2] font-normal">PPS</span>
          </div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Real-time packet throughput</div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[10px] uppercase font-mono text-[#667085]">Bandwidth Rate</div>
          <div className="text-2xl font-bold font-mono text-[#A78BFA] mt-1">{trafficRateStr}</div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Wire transfer throughput</div>
        </div>

        <div className="bg-[#121720] border border-[#202735] rounded-xl p-3 flex flex-col justify-between">
          <div className="text-[10px] uppercase font-mono text-[#667085]">TCP / UDP / ICMP</div>
          <div className="text-lg font-bold font-mono text-[#F4F7FB] mt-1 flex items-center gap-2">
            <span className="text-[#60A5FA]">{stats.tcp_count || 0}</span> /{' '}
            <span className="text-[#A78BFA]">{stats.udp_count || 0}</span> /{' '}
            <span className="text-[#35D07F]">{stats.icmp_count || 0}</span>
          </div>
          <div className="text-[10px] text-[#9AA4B2] mt-1">Protocol frame counter</div>
        </div>

        {/* Live Sparkline Graph */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-2.5 flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between text-[10px] uppercase font-mono text-[#667085]">
            <span>PPS History</span>
            <span className="text-[#62E8F7]">{rateHistory.length}s</span>
          </div>
          <div className="w-full h-8 flex items-center justify-center my-auto">
            {chartPoints ? (
              <svg viewBox="0 0 300 50" className="w-full h-full overflow-visible">
                <polyline
                  fill="none"
                  stroke="#62E8F7"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={chartPoints}
                />
              </svg>
            ) : (
              <span className="text-[10px] text-[#667085]">Awaiting packets...</span>
            )}
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#121720] border border-[#202735] rounded-xl p-2.5 flex-shrink-0">
        {/* Protocol Selector */}
        <div className="flex items-center gap-1 text-[11px]">
          <span className="text-[10px] font-mono text-[#667085] uppercase mr-1">Proto:</span>
          {['ALL', 'TCP', 'UDP', 'ICMP'].map((proto) => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                protocolFilter === proto
                  ? 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40'
                  : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>

        {/* Classification Filter */}
        <div className="flex items-center gap-1 text-[11px]">
          <span className="text-[10px] font-mono text-[#667085] uppercase mr-1">Class:</span>
          {[
            { id: 'ALL', label: 'All' },
            { id: 'BENIGN', label: 'Normal' },
            { id: 'ATTACK', label: 'Threats' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setPredictionFilter(item.id)}
              className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                predictionFilter === item.id
                  ? item.id === 'ATTACK'
                    ? 'bg-[#FF3B5C]/20 text-[#FF5C6C] border border-[#FF3B5C]/40'
                    : 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40'
                  : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Search within table */}
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

      {/* Live Table */}
      <div className="flex-1 bg-[#121720] border border-[#202735] rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#161B25] sticky top-0 z-10 text-[10px] uppercase font-mono tracking-wider text-[#667085] border-b border-[#202735]">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3 text-right">Port</th>
                <th className="py-2.5 px-3 text-right">Length</th>
                <th className="py-2.5 px-3 text-center">Prediction</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#202735]/60 text-[11px]">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#667085]">
                    {isMonitoring
                      ? 'Listening for network packets matching filter...'
                      : 'Monitoring is offline. Click "START MONITORING" on the Dashboard to capture live traffic.'}
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt, idx) => {
                  const isThreat = Boolean(pkt.is_attack);
                  const conf = pkt.confidence_pct ? `${pkt.confidence_pct.toFixed(1)}%` : '—';
                  return (
                    <tr
                      key={pkt.id || idx}
                      className={`hover:bg-[#161B25]/80 transition-colors ${
                        isThreat ? 'bg-[#FF3B5C]/5' : ''
                      }`}
                    >
                      <td className="py-2 px-3 font-mono text-[10px] text-[#9AA4B2]">
                        {pkt.timestamp_str ? pkt.timestamp_str.split(' ')[1] || pkt.timestamp_str : 'Live'}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#F4F7FB]">{pkt.src_ip || '—'}</td>
                      <td className="py-2 px-3 font-mono text-[#9AA4B2]">{pkt.dst_ip || '—'}</td>
                      <td className="py-2 px-3">
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-[#161B25] border border-[#202735] text-[#60A5FA]">
                          {pkt.protocol || 'IP'}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-right text-[#9AA4B2]">
                        {pkt.dst_port || pkt.src_port || '—'}
                      </td>
                      <td className="py-2 px-3 font-mono text-right text-[#9AA4B2]">
                        {pkt.length ? `${pkt.length} B` : '—'}
                      </td>
                      <td className="py-2 px-3 text-center">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold inline-flex items-center gap-1 border ${
                            isThreat
                              ? 'bg-[#FF3B5C]/15 border-[#FF3B5C]/40 text-[#FF5C6C]'
                              : 'bg-[#35D07F]/15 border-[#35D07F]/40 text-[#35D07F]'
                          }`}
                        >
                          {isThreat ? <ShieldAlert className="w-2.5 h-2.5" /> : <ShieldCheck className="w-2.5 h-2.5" />}
                          {pkt.prediction || (isThreat ? 'ATTACK' : 'BENIGN')}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-right text-[#F4F7FB]">{conf}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <div className="px-3 py-1.5 bg-[#161B25] border-t border-[#202735] text-[10px] text-[#667085] flex items-center justify-between">
          <span>Showing {filteredPackets.length} recent packets</span>
          <span>Buffer capacity: 150 packets</span>
        </div>
      </div>
    </div>
  );
}
