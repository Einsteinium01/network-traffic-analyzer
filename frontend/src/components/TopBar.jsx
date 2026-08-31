import React, { useState, useRef, useEffect } from 'react';
import {
  Search,
  Wifi,
  Cpu,
  AlertTriangle,
  ShieldAlert,
  GitBranch,
  Activity,
  X,
  User,
} from 'lucide-react';

import { useMonitoring } from '../context/MonitoringContext';

export default function TopBar({ setActiveTab }) {
  const {
    isMonitoring,
    activeMode,
    activeInterface,
    selectedMode,
    setSelectedMode,
    selectedInterface,
    setSelectedInterface,
    interfaces,
    monitoringState,
    alerts,
    flows,
    recentPackets,
    error,
    isLoading,
  } = useMonitoring();

  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const searchRef = useRef(null);

  // Close search dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (searchRef.current && !searchRef.current.contains(event.target)) {
        setIsSearchOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute real search results across available live state
  const cleanQuery = searchQuery.trim().toLowerCase();
  const searchResults = React.useMemo(() => {
    if (!cleanQuery) return { threats: [], flows: [], packets: [] };

    const matchingThreats = alerts
      .filter(
        (a) =>
          (a.src_ip && a.src_ip.toLowerCase().includes(cleanQuery)) ||
          (a.dst_ip && a.dst_ip.toLowerCase().includes(cleanQuery)) ||
          (a.attack_type && a.attack_type.toLowerCase().includes(cleanQuery)) ||
          (a.protocol && a.protocol.toLowerCase().includes(cleanQuery)) ||
          (a.severity && a.severity.toLowerCase().includes(cleanQuery)) ||
          String(a.src_port || '').includes(cleanQuery) ||
          String(a.dst_port || '').includes(cleanQuery)
      )
      .slice(0, 5);

    const matchingFlows = flows
      .filter(
        (f) =>
          (f.src_ip && f.src_ip.toLowerCase().includes(cleanQuery)) ||
          (f.dst_ip && f.dst_ip.toLowerCase().includes(cleanQuery)) ||
          (f.protocol && f.protocol.toLowerCase().includes(cleanQuery)) ||
          (f.flow_id && f.flow_id.toLowerCase().includes(cleanQuery)) ||
          String(f.src_port || '').includes(cleanQuery) ||
          String(f.dst_port || '').includes(cleanQuery)
      )
      .slice(0, 5);

    const matchingPackets = recentPackets
      .filter(
        (p) =>
          (p.src_ip && p.src_ip.toLowerCase().includes(cleanQuery)) ||
          (p.dst_ip && p.dst_ip.toLowerCase().includes(cleanQuery)) ||
          (p.protocol && p.protocol.toLowerCase().includes(cleanQuery)) ||
          (p.prediction && p.prediction.toLowerCase().includes(cleanQuery)) ||
          (p.attack_type && p.attack_type.toLowerCase().includes(cleanQuery)) ||
          String(p.src_port || '').includes(cleanQuery) ||
          String(p.dst_port || '').includes(cleanQuery)
      )
      .slice(0, 5);

    return {
      threats: matchingThreats,
      flows: matchingFlows,
      packets: matchingPackets,
    };
  }, [cleanQuery, alerts, flows, recentPackets]);

  const totalMatches =
    searchResults.threats.length + searchResults.flows.length + searchResults.packets.length;

  const handleSelectResult = (tabName) => {
    setIsSearchOpen(false);
    setSearchQuery('');
    if (setActiveTab) {
      setActiveTab(tabName);
    }
  };

  // Status badge style derived purely from authoritative backend monitoringState
  const statusConfig = {
    ACTIVE: {
      bg: 'bg-[#35D07F]/10 border-[#35D07F]/30 text-[#35D07F]',
      dot: 'bg-[#35D07F] animate-pulse',
      label: `● MONITORING ACTIVE [${activeMode}: ${activeInterface || selectedInterface || 'Auto'}]`,
    },
    STARTING: {
      bg: 'bg-[#62E8F7]/10 border-[#62E8F7]/30 text-[#62E8F7]',
      dot: 'bg-[#62E8F7] animate-ping',
      label: '◌ STARTING CAPTURE ENGINE...',
    },
    STOPPING: {
      bg: 'bg-[#F5B84B]/10 border-[#F5B84B]/30 text-[#F5B84B]',
      dot: 'bg-[#F5B84B] animate-pulse',
      label: '◌ STOPPING CAPTURE...',
    },
    ERROR: {
      bg: 'bg-[#FF3B5C]/10 border-[#FF3B5C]/30 text-[#FF5C6C]',
      dot: 'bg-[#FF3B5C]',
      label: '! MONITORING ERROR',
    },
    IDLE: {
      bg: 'bg-[#121720] border-[#202735] text-[#9AA4B2]',
      dot: 'bg-[#667085]',
      label: '○ MONITORING IDLE',
    },
  };

  const currStatus = statusConfig[monitoringState] || statusConfig.IDLE;

  return (
    <header className="h-14 border-b border-[#202735] bg-[#090D13]/80 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between px-5">
      {/* Left: Search Input & Error Notification */}
      <div className="flex items-center gap-3 relative" ref={searchRef}>
        <div className="relative w-64 md:w-80">
          <Search className="w-3.5 h-3.5 text-[#667085] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setIsSearchOpen(true);
            }}
            onFocus={() => {
              if (searchQuery.trim()) setIsSearchOpen(true);
            }}
            placeholder="SEARCH NETWORK (IP, Port, Protocol, Threat)..."
            className="w-full bg-[#121720] border border-[#202735] focus:border-[#62E8F7]/50 focus:outline-none rounded-xl py-1.5 pl-9 pr-7 text-[11px] tracking-wider text-[#F4F7FB] placeholder-[#667085] transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => {
                setSearchQuery('');
                setIsSearchOpen(false);
              }}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#667085] hover:text-[#F4F7FB]"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Global Search Results Dropdown */}
        {isSearchOpen && searchQuery.trim() && (
          <div className="absolute top-11 left-0 w-96 bg-[#121720] border border-[#202735] rounded-xl shadow-2xl overflow-hidden z-50 text-[11px]">
            <div className="px-3 py-2 border-b border-[#202735] flex items-center justify-between bg-[#161B25]">
              <span className="text-[10px] uppercase font-mono tracking-wider text-[#9AA4B2]">
                Search Results ({totalMatches})
              </span>
              <span className="text-[9px] text-[#667085]">Esc to close</span>
            </div>

            <div className="max-h-80 overflow-y-auto p-2 space-y-3">
              {totalMatches === 0 ? (
                <div className="p-4 text-center text-[#667085] text-xs">
                  No matching network activity found.
                </div>
              ) : (
                <>
                  {/* Threats Matches */}
                  {searchResults.threats.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-[#FF5C6C] px-2 mb-1 flex items-center gap-1.5 uppercase">
                        <ShieldAlert className="w-3 h-3" /> Detected Threats
                      </div>
                      <div className="space-y-1">
                        {searchResults.threats.map((t, idx) => (
                          <div
                            key={idx}
                            onClick={() => handleSelectResult('threats')}
                            className="px-2.5 py-1.5 rounded-lg bg-[#161B25]/60 hover:bg-[#202735] cursor-pointer flex items-center justify-between text-[#F4F7FB] transition-colors"
                          >
                            <span className="font-semibold text-[#FF5C6C]">
                              {t.attack_type || 'Threat'}
                            </span>
                            <span className="font-mono text-[10px] text-[#9AA4B2]">
                              {t.src_ip} → {t.dst_ip}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Flow Matches */}
                  {searchResults.flows.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-[#62E8F7] px-2 mb-1 flex items-center gap-1.5 uppercase">
                        <GitBranch className="w-3 h-3" /> Active Network Flows
                      </div>
                      <div className="space-y-1">
                        {searchResults.flows.map((f, idx) => (
                          <div
                            key={idx}
                            onClick={() => handleSelectResult('flows')}
                            className="px-2.5 py-1.5 rounded-lg bg-[#161B25]/60 hover:bg-[#202735] cursor-pointer flex items-center justify-between text-[#F4F7FB] transition-colors"
                          >
                            <span className="font-mono text-[10px] text-[#62E8F7]">
                              {f.protocol} {f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port}
                            </span>
                            <span className="text-[9px] text-[#9AA4B2]">
                              {f.total_packets} pkts
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Packet Matches */}
                  {searchResults.packets.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-[#A78BFA] px-2 mb-1 flex items-center gap-1.5 uppercase">
                        <Activity className="w-3 h-3" /> Live Packets
                      </div>
                      <div className="space-y-1">
                        {searchResults.packets.map((p, idx) => (
                          <div
                            key={idx}
                            onClick={() => handleSelectResult('live-traffic')}
                            className="px-2.5 py-1.5 rounded-lg bg-[#161B25]/60 hover:bg-[#202735] cursor-pointer flex items-center justify-between text-[#F4F7FB] transition-colors"
                          >
                            <span className="font-mono text-[10px]">
                              {p.src_ip} → {p.dst_ip} ({p.protocol})
                            </span>
                            <span
                              className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${
                                p.is_attack
                                  ? 'bg-[#FF3B5C]/20 text-[#FF5C6C]'
                                  : 'bg-[#35D07F]/20 text-[#35D07F]'
                              }`}
                            >
                              {p.prediction || 'BENIGN'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Explicit Backend Error Banner */}
        {error && (
          <div className="hidden xl:flex items-center gap-1.5 px-3 py-1 rounded-xl bg-[#FF5C6C]/10 border border-[#FF5C6C]/30 text-[#FF5C6C] text-[11px] animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="truncate max-w-xs">{error}</span>
          </div>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Interface Selector Dropdown (PERSISTENT STATE) */}
        <div className="flex items-center gap-1.5 bg-[#121720] border border-[#202735] rounded-xl px-2.5 py-1 text-[11px] text-[#F4F7FB]">
          <Wifi className="w-3.5 h-3.5 text-[#62E8F7]" />
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isLoading || isMonitoring}
            title={
              isMonitoring
                ? 'Stop monitoring before changing network interface.'
                : 'Select network capture interface'
            }
            className="bg-transparent focus:outline-none text-[11px] text-[#F4F7FB] font-medium cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {interfaces.length === 0 ? (
              <option value="" className="bg-[#121720] text-[#F4F7FB]">
                Auto / Default
              </option>
            ) : (
              interfaces.map((iface) => (
                <option
                  key={iface.name}
                  value={iface.name}
                  className="bg-[#121720] text-[#F4F7FB]"
                >
                  {iface.name} ({iface.ip}) {iface.status === 'UP' ? '●' : ''}
                </option>
              ))
            )}
          </select>
        </div>

        {/* Mode Selector Switch (PERSISTENT STATE: LIVE vs SIMULATION) */}
        <div className="flex items-center bg-[#121720] border border-[#202735] rounded-xl p-0.5 text-[10px] font-semibold">
          <button
            onClick={() => setSelectedMode('LIVE')}
            disabled={isLoading || isMonitoring}
            title={
              isMonitoring
                ? 'Stop monitoring to change capture mode.'
                : 'Capture live packets from local network adapter'
            }
            className={`px-2.5 py-1 rounded-lg transition-all flex items-center gap-1 disabled:opacity-60 disabled:cursor-not-allowed ${
              selectedMode === 'LIVE'
                ? 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40 shadow-sm'
                : 'text-[#667085] hover:text-[#F4F7FB]'
            }`}
          >
            <Wifi className="w-3 h-3" />
            LIVE
          </button>
          <button
            onClick={() => setSelectedMode('SIMULATION')}
            disabled={isLoading || isMonitoring}
            title={
              isMonitoring
                ? 'Stop monitoring to change capture mode.'
                : 'Replay simulated traffic streams'
            }
            className={`px-2.5 py-1 rounded-lg transition-all flex items-center gap-1 disabled:opacity-60 disabled:cursor-not-allowed ${
              selectedMode === 'SIMULATION'
                ? 'bg-[#FFC043]/20 text-[#FFC043] border border-[#FFC043]/40 shadow-sm'
                : 'text-[#667085] hover:text-[#F4F7FB]'
            }`}
          >
            <Cpu className="w-3 h-3" />
            SIM
          </button>
        </div>

        {/* Global Status Indicator (DISPLAY-ONLY PILL - NO START/STOP CLICK HANDLER) */}
        <div
          className={`px-3 py-1 rounded-full border text-[11px] font-semibold flex items-center gap-2 select-none ${currStatus.bg}`}
        >
          <span className={`w-2 h-2 rounded-full ${currStatus.dot}`} />
          <span className="font-mono tracking-tight">{currStatus.label}</span>
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 border-l border-[#202735]">
          <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-[#161B25] to-[#202735] border border-[#303A4A] flex items-center justify-center text-[#62E8F7]">
            <User className="w-3.5 h-3.5" />
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-[11px] font-semibold text-[#F4F7FB]">Security Admin</div>
            <div className="text-[9px] text-[#667085]">SOC Analyst</div>
          </div>
        </div>
      </div>
    </header>
  );
}


