import React, { useState } from 'react';
import {
  Download,
  Search,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';
import apiService from '../services/api';

export default function LogsPage() {
  const { alerts, recentPackets } = useMonitoring();
  const [logType, setLogType] = useState('ALERTS');
  const [searchFilter, setSearchFilter] = useState('');

  const cleanSearch = searchFilter.trim().toLowerCase();
  const displayedRecords =
    logType === 'ALERTS'
      ? alerts.filter((a) => {
          if (!cleanSearch) return true;
          return (
            (a.src_ip || '').toLowerCase().includes(cleanSearch) ||
            (a.dst_ip || '').toLowerCase().includes(cleanSearch) ||
            (a.attack_type || '').toLowerCase().includes(cleanSearch) ||
            (a.severity || '').toLowerCase().includes(cleanSearch)
          );
        })
      : recentPackets.filter((p) => {
          if (!cleanSearch) return true;
          return (
            (p.src_ip || '').toLowerCase().includes(cleanSearch) ||
            (p.dst_ip || '').toLowerCase().includes(cleanSearch) ||
            (p.protocol || '').toLowerCase().includes(cleanSearch) ||
            (p.prediction || '').toLowerCase().includes(cleanSearch)
          );
        });

  const handleExportCsv = () => {
    const type = logType === 'ALERTS' ? 'alerts' : 'logs';
    const url = apiService.getExportCsvUrl(type, 500);
    window.open(url, '_blank');
  };

  return (
    <div className="h-full flex flex-col space-y-3 max-h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">Security Logs</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#62E8F7]/15 text-[#62E8F7] border border-[#62E8F7]/30">
              Audit Record
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Historical audit log of security events and inspected network packets.
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          className="px-3 py-1.5 rounded-xl border border-[#303A4A] bg-[#161B25] hover:bg-[#202735] text-xs font-semibold text-[#62E8F7] flex items-center gap-1.5 transition-all"
        >
          <Download className="w-3.5 h-3.5" />
          <span>EXPORT CSV</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#121720] border border-[#202735] rounded-xl p-2.5 flex-shrink-0">
        <div className="flex items-center gap-1 text-[11px]">
          <span className="text-[10px] font-mono text-[#667085] uppercase mr-1">Log Type:</span>
          <button
            onClick={() => setLogType('ALERTS')}
            className={`px-3 py-1 rounded-lg font-medium transition-all ${
              logType === 'ALERTS'
                ? 'bg-[#FF3B5C]/20 text-[#FF5C6C] border border-[#FF3B5C]/40'
                : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
            }`}
          >
            Threat Alerts ({alerts.length})
          </button>
          <button
            onClick={() => setLogType('PACKETS')}
            className={`px-3 py-1 rounded-lg font-medium transition-all ${
              logType === 'PACKETS'
                ? 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40'
                : 'text-[#9AA4B2] hover:bg-[#161B25] hover:text-[#F4F7FB]'
            }`}
          >
            All Packets ({recentPackets.length})
          </button>
        </div>

        <div className="relative w-48 sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#667085] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search logs..."
            className="w-full bg-[#161B25] border border-[#202735] rounded-lg py-1 pl-8 pr-2.5 text-[11px] text-[#F4F7FB] placeholder-[#667085] focus:outline-none focus:border-[#62E8F7]/40"
          />
        </div>
      </div>

      {/* Logs Table (Section 35 of design.md) */}
      <div className="flex-1 bg-[#121720] border border-[#202735] rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#161B25] sticky top-0 z-10 text-[10px] uppercase font-mono tracking-wider text-[#667085] border-b border-[#202735]">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Destination Endpoint</th>
                <th className="py-2.5 px-3">{logType === 'ALERTS' ? 'Attack Event' : 'Protocol'}</th>
                <th className="py-2.5 px-3 text-center">{logType === 'ALERTS' ? 'Severity' : 'Prediction'}</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#202735]/60 text-[11px]">
              {displayedRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-16 text-center text-[#667085]">
                    No log entries matching the selected criteria.
                  </td>
                </tr>
              ) : (
                displayedRecords.map((r, idx) => {
                  const isThreat = logType === 'ALERTS' || Boolean(r.is_attack);
                  return (
                    <tr key={idx} className="hover:bg-[#161B25]/80 transition-colors">
                      <td className="py-2 px-3 font-mono text-[10px] text-[#9AA4B2]">
                        {r.timestamp_str || 'Live Event'}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#F4F7FB]">
                        {r.src_ip}{r.src_port ? `:${r.src_port}` : ''}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#9AA4B2]">
                        {r.dst_ip}{r.dst_port ? `:${r.dst_port}` : ''}
                      </td>
                      <td className="py-2 px-3 font-medium">
                        {logType === 'ALERTS' ? (
                          <span className="text-[#FF5C6C]">{r.attack_type || 'Malicious Intrusion'}</span>
                        ) : (
                          <span className="text-[#60A5FA] font-mono">{r.protocol || 'IP'}</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-center">
                        {logType === 'ALERTS' ? (
                          <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold bg-[#FF3B5C]/15 border border-[#FF3B5C]/30 text-[#FF5C6C]">
                            {r.severity || 'HIGH'}
                          </span>
                        ) : (
                          <span
                            className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold border ${
                              isThreat
                                ? 'bg-[#FF3B5C]/15 border-[#FF3B5C]/30 text-[#FF5C6C]'
                                : 'bg-[#35D07F]/15 border-[#35D07F]/30 text-[#35D07F]'
                            }`}
                          >
                            {r.prediction || 'BENIGN'}
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 font-mono text-right text-[#F4F7FB]">
                        {r.confidence_pct ? `${r.confidence_pct.toFixed(1)}%` : '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
