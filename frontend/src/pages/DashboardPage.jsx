import React from 'react';
import { Play, Square, Activity, Network, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';
import KpiCard from '../components/KpiCard';
import CircularMetric from '../components/CircularMetric';
import NetworkVisPlaceholder from '../components/NetworkVisPlaceholder';
import SecurityFeedPlaceholder from '../components/SecurityFeedPlaceholder';

export default function DashboardPage() {
  const {
    isMonitoring,
    activeMode,
    activeInterface,
    selectedMode,
    selectedInterface,
    stats,
    recentPackets,
    startMonitoring,
    stopMonitoring,
    monitoringState,
    isLoading,
    error,
  } = useMonitoring();

  // Dynamic throughput formatting (Single true rate from backend)
  const bytesPerSec = stats.bytes_per_second || 0;
  let trafficRateStr = '0.00 KB/s';
  if (bytesPerSec >= 1024 * 1024) {
    trafficRateStr = (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
  } else if (bytesPerSec >= 1024) {
    trafficRateStr = (bytesPerSec / 1024).toFixed(1) + ' KB/s';
  } else {
    trafficRateStr = bytesPerSec.toFixed(0) + ' B/s';
  }

  const totalPacketsStr = stats.total_packets ? stats.total_packets.toLocaleString() : '0';
  const threatsStr = stats.attack_packets !== undefined ? stats.attack_packets.toString() : '0';
  const systemHealthStr = isMonitoring ? (stats.threat_level === 'LOW' ? 'Stable' : stats.threat_level) : 'Idle';
  const activeFlowsStr = stats.active_flows !== undefined ? stats.active_flows.toString() : '0';

  const ppsStr = stats.packets_per_second ? stats.packets_per_second.toLocaleString() : '0';
  const normalPct = stats.total_packets > 0 ? (stats.normal_pct !== undefined ? stats.normal_pct : 100) : 100;
  const attackPct = stats.total_packets > 0 ? (stats.attack_pct !== undefined ? stats.attack_pct : 0) : 0;

  // Real model confidence from streaming predictions
  const confidenceSamples = recentPackets.filter((p) => typeof p.confidence_pct === 'number' && p.confidence_pct > 0);
  const avgConfidence = confidenceSamples.length
    ? confidenceSamples.reduce((sum, p) => sum + p.confidence_pct, 0) / confidenceSamples.length
    : null;
  const confidenceStr = avgConfidence !== null ? `${avgConfidence.toFixed(1)}%` : '—';
  const confidencePct = avgConfidence !== null ? avgConfidence : 0;

  const handleToggle = () => {
    if (isMonitoring) {
      stopMonitoring();
    } else {
      startMonitoring();
    }
  };

  return (
    <div className="h-full flex flex-col justify-between space-y-3 max-h-full overflow-hidden">
      {/* Error Alert Banner if Backend connection fails */}
      {error && (
        <div className="px-3 py-2 bg-[#FF3B5C]/15 border border-[#FF3B5C]/30 text-[#FF5C6C] rounded-lg text-xs flex items-center justify-between flex-shrink-0">
          <span>{error}</span>
        </div>
      )}

      {/* Dashboard Page Header */}
      <div className="flex items-center justify-between gap-4 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#F4F7FB]">
              Network Overview
            </h1>
            <span
              className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                isMonitoring
                  ? activeMode === 'LIVE'
                    ? 'bg-[#35D07F]/15 border-[#35D07F]/40 text-[#35D07F]'
                    : 'bg-[#FFC043]/15 border-[#FFC043]/40 text-[#FFC043]'
                  : 'bg-[#121720] border-[#202735] text-[#9AA4B2]'
              }`}
            >
              {isMonitoring
                ? activeMode === 'LIVE'
                  ? `LIVE: ${activeInterface || selectedInterface || 'Auto'}`
                  : 'SIMULATION'
                : `TARGET: [${selectedMode}] ${selectedInterface || 'Auto'}`}
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Real-time visibility into live network traffic and security events.
          </p>
        </div>

        {/* Primary Start / Stop Monitoring Button */}
        <div>
          <button
            onClick={handleToggle}
            disabled={isLoading}
            className={`px-4 py-2 rounded-[10px] text-[11px] font-semibold uppercase tracking-wider flex items-center gap-2 transition-all ${
              isMonitoring
                ? 'bg-[#FF3B5C]/15 border border-[#FF3B5C]/40 text-[#FF5C6C] hover:bg-[#FF3B5C]/25 glow-red'
                : 'gradient-accent-btn'
            }`}
          >
            {isMonitoring ? (
              <>
                <Square className="w-3 h-3 fill-current" />
                <span>{isLoading || monitoringState === 'STOPPING' ? 'STOPPING...' : 'STOP MONITORING'}</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 fill-current" />
                <span>{isLoading || monitoringState === 'STARTING' ? 'STARTING...' : 'START MONITORING'}</span>
              </>
            )}
          </button>
        </div>
      </div>


      {/* Row 1: 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 flex-shrink-0">
        <KpiCard
          label="TOTAL PACKETS"
          value={totalPacketsStr}
          supporting={`${normalPct}% Normal traffic`}
          icon={Activity}
          iconTint="cyan"
        />
        <KpiCard
          label="TRAFFIC RATE"
          value={trafficRateStr}
          supporting={`${activeFlowsStr} Active Flows`}
          icon={Network}
          iconTint="blue"
        />
        <KpiCard
          label="THREATS DETECTED"
          value={threatsStr}
          supporting={`${attackPct}% Threat ratio`}
          icon={ShieldAlert}
          iconTint="magenta"
        />
        <KpiCard
          label="SYSTEM HEALTH"
          value={systemHealthStr}
          supporting={isMonitoring ? `Threat Level: ${stats.threat_level}` : 'Engine standing by'}
          icon={ShieldCheck}
          iconTint="green"
        />
      </div>

      {/* Row 2: Central Network Visualization (2 cols) + Security Feed (1 col) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3.5 flex-1 min-h-0">
        <div className="lg:col-span-2 h-full min-h-0">
          <NetworkVisPlaceholder />
        </div>
        <div className="lg:col-span-1 h-full min-h-0">
          <SecurityFeedPlaceholder />
        </div>
      </div>

      {/* Row 3: 3 Circular Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 flex-shrink-0">
        <CircularMetric
          label="PACKETS / SEC"
          value={ppsStr}
          subtext="Live packet capture rate"
          percentage={Math.min((stats.packets_per_second / 2000) * 100, 100)}
          color="cyan"
        />
        <CircularMetric
          label="DETECTION RATE"
          value={`${attackPct}%`}
          subtext="Share of traffic flagged as attacks"
          percentage={attackPct}
          color="purple"
        />
        <CircularMetric
          label="MODEL CONFIDENCE"
          value={confidenceStr}
          subtext="Average prediction confidence"
          percentage={confidencePct}
          color="magenta"
        />
      </div>
    </div>
  );
}
