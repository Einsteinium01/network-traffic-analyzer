import React from 'react';
import {
  PieChart,
  BarChart3,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function AnalyticsPage() {
  const { stats, alerts, recentPackets } = useMonitoring();


  const attackTypes = {};
  alerts.forEach((a) => {
    const type = a.attack_type || 'Unknown Threat';
    attackTypes[type] = (attackTypes[type] || 0) + 1;
  });

  const totalProtocols = (stats.tcp_count || 0) + (stats.udp_count || 0) + (stats.icmp_count || 0) || 1;
  const tcpPct = Math.round(((stats.tcp_count || 0) / totalProtocols) * 100);
  const udpPct = Math.round(((stats.udp_count || 0) / totalProtocols) * 100);
  const icmpPct = Math.round(((stats.icmp_count || 0) / totalProtocols) * 100);

  const srcIpCounts = {};
  recentPackets.forEach((p) => {
    if (p.src_ip) srcIpCounts[p.src_ip] = (srcIpCounts[p.src_ip] || 0) + 1;
  });
  const topSrcIps = Object.entries(srcIpCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const dstPortCounts = {};
  recentPackets.forEach((p) => {
    const port = p.dst_port || p.src_port;
    if (port) dstPortCounts[port] = (dstPortCounts[port] || 0) + 1;
  });
  const topPorts = Object.entries(dstPortCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="h-full flex flex-col space-y-3.5 max-h-full overflow-y-auto pr-1">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">Network Analytics</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#A78BFA]/15 text-[#A78BFA] border border-[#A78BFA]/30">
              Live Session Analytics
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Statistical breakdown of active network flows, protocol distributions, and threat vectors.
          </p>
        </div>
      </div>

      {/* Grid of Analytics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {/* Protocol Distribution Card */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-[#F4F7FB] flex items-center gap-1.5">
                <PieChart className="w-4 h-4 text-[#62E8F7]" />
                Protocol Breakdown
              </h3>
              <span className="text-[10px] font-mono text-[#667085]">LIVE PACKETS</span>
            </div>
            <p className="text-[11px] text-[#9AA4B2] mb-3">
              Distribution of transport layer protocols observed across current capture session.
            </p>

            <div className="space-y-2.5">
              <div>
                <div className="flex justify-between text-[11px] font-mono mb-1">
                  <span className="text-[#60A5FA]">TCP ({stats.tcp_count || 0} pkts)</span>
                  <span className="text-[#F4F7FB]">{tcpPct}%</span>
                </div>
                <div className="w-full bg-[#161B25] h-2 rounded-full overflow-hidden">
                  <div className="bg-[#60A5FA] h-full rounded-full" style={{ width: `${tcpPct}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] font-mono mb-1">
                  <span className="text-[#A78BFA]">UDP ({stats.udp_count || 0} pkts)</span>
                  <span className="text-[#F4F7FB]">{udpPct}%</span>
                </div>
                <div className="w-full bg-[#161B25] h-2 rounded-full overflow-hidden">
                  <div className="bg-[#A78BFA] h-full rounded-full" style={{ width: `${udpPct}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] font-mono mb-1">
                  <span className="text-[#35D07F]">ICMP ({stats.icmp_count || 0} pkts)</span>
                  <span className="text-[#F4F7FB]">{icmpPct}%</span>
                </div>
                <div className="w-full bg-[#161B25] h-2 rounded-full overflow-hidden">
                  <div className="bg-[#35D07F] h-full rounded-full" style={{ width: `${icmpPct}%` }} />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Attack Category Breakdown Card */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-[#F4F7FB] flex items-center gap-1.5">
                <BarChart3 className="w-4 h-4 text-[#FF5C6C]" />
                Threat Vector Distribution
              </h3>
              <span className="text-[10px] font-mono text-[#667085]">{alerts.length} ALERTS</span>
            </div>
            <p className="text-[11px] text-[#9AA4B2] mb-3">
              Classification breakdown of detected malicious traffic categories.
            </p>

            {Object.keys(attackTypes).length === 0 ? (
              <div className="py-6 text-center text-[#667085] text-xs">
                No threat alerts recorded in the current session.
              </div>
            ) : (
              <div className="space-y-2">
                {Object.entries(attackTypes).map(([type, count]) => {
                  const pct = Math.round((count / alerts.length) * 100);
                  return (
                    <div key={type}>
                      <div className="flex justify-between text-[11px] font-mono mb-1">
                        <span className="text-[#FF5C6C]">{type}</span>
                        <span className="text-[#F4F7FB]">{count} ({pct}%)</span>
                      </div>
                      <div className="w-full bg-[#161B25] h-2 rounded-full overflow-hidden">
                        <div
                          className="bg-[#FF3B5C] h-full rounded-full"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Top Active Source IP Endpoints */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-[#F4F7FB]">Top Source Host Endpoints</h3>
            <span className="text-[10px] font-mono text-[#667085]">LIVE BUFFER</span>
          </div>
          <div className="space-y-2 mt-3">
            {topSrcIps.length === 0 ? (
              <div className="py-4 text-center text-[#667085] text-xs">No active host data</div>
            ) : (
              topSrcIps.map(([ip, count], idx) => (
                <div
                  key={ip}
                  className="flex items-center justify-between p-2 rounded-lg bg-[#161B25] border border-[#202735] text-[11px]"
                >
                  <span className="font-mono text-[#F4F7FB]">
                    #{idx + 1} {ip}
                  </span>
                  <span className="font-mono text-[#62E8F7] font-semibold">{count} packets</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Targeted Destination Ports */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-[#F4F7FB]">Top Targeted Network Ports</h3>
            <span className="text-[10px] font-mono text-[#667085]">LIVE BUFFER</span>
          </div>
          <div className="space-y-2 mt-3">
            {topPorts.length === 0 ? (
              <div className="py-4 text-center text-[#667085] text-xs">No active port data</div>
            ) : (
              topPorts.map(([port, count], idx) => (
                <div
                  key={port}
                  className="flex items-center justify-between p-2 rounded-lg bg-[#161B25] border border-[#202735] text-[11px]"
                >
                  <span className="font-mono text-[#F4F7FB]">
                    #{idx + 1} Port {port} {port === '443' ? '(HTTPS)' : port === '80' ? '(HTTP)' : port === '53' ? '(DNS)' : ''}
                  </span>
                  <span className="font-mono text-[#A78BFA] font-semibold">{count} hits</span>
                </div>
              ))
            )}

          </div>
        </div>
      </div>
    </div>
  );
}
