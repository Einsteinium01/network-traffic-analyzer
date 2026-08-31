import React, { useMemo } from 'react';
import { Radio, ShieldAlert } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function LiveTrafficChart() {
  const { isMonitoring, stats, trafficHistory, alerts } = useMonitoring();

  // Current live metrics
  const pps = stats.packets_per_second ? stats.packets_per_second.toLocaleString() : '0';
  const bpsVal = stats.bytes_per_second || 0;
  const bps =
    bpsVal >= 1024 * 1024
      ? `${(bpsVal / (1024 * 1024)).toFixed(2)} MB/s`
      : bpsVal >= 1024
        ? `${(bpsVal / 1024).toFixed(1)} KB/s`
        : `${bpsVal.toFixed(0)} B/s`;
  const activeFlows = stats.active_flows !== undefined ? stats.active_flows.toLocaleString() : '0';

  // Chart dimensions
  const W = 600;
  const H = 140;
  const PAD_L = 0;
  const PAD_R = 0;
  const PAD_T = 8;
  const PAD_B = 20;
  const chartW = W - PAD_L - PAD_R;
  const chartH = H - PAD_T - PAD_B;

  // Build SVG paths from trafficHistory
  const { ppsPath, ppsFillPath, bpsPath, gridLines, threatMarkers } = useMemo(() => {
    const now = Date.now();
    const windowMs = 60000;
    const startT = now - windowMs;

    const visible = trafficHistory.filter((p) => p.t >= startT);

    if (visible.length < 2) {
      return { ppsPath: '', ppsFillPath: '', bpsPath: '', gridLines: [], threatMarkers: [] };
    }

    let mPps = 10;
    let mBps = 1024;
    for (const p of visible) {
      if (p.pps > mPps) mPps = p.pps;
      if (p.bps > mBps) mBps = p.bps;
    }
    mPps = Math.ceil(mPps * 1.15);
    mBps = Math.ceil(mBps * 1.15);

    const toX = (t) => PAD_L + ((t - startT) / windowMs) * chartW;
    const toPpsY = (v) => PAD_T + chartH - (v / mPps) * chartH;
    const toBpsY = (v) => PAD_T + chartH - (v / mBps) * chartH;

    let pp = '';
    let bp = '';
    for (let i = 0; i < visible.length; i++) {
      const x = toX(visible[i].t).toFixed(1);
      const yp = toPpsY(visible[i].pps).toFixed(1);
      const yb = toBpsY(visible[i].bps).toFixed(1);
      pp += `${i === 0 ? 'M' : 'L'}${x},${yp}`;
      bp += `${i === 0 ? 'M' : 'L'}${x},${yb}`;
    }

    // Fill area for PPS
    const lastX = toX(visible[visible.length - 1].t).toFixed(1);
    const firstX = toX(visible[0].t).toFixed(1);
    const bottomY = (PAD_T + chartH).toFixed(1);
    const pFill = `${pp}L${lastX},${bottomY}L${firstX},${bottomY}Z`;

    // Grid lines (4 horizontal)
    const gLines = [];
    for (let i = 0; i <= 4; i++) {
      const y = PAD_T + (chartH / 4) * i;
      const val = Math.round(mPps * (1 - i / 4));
      gLines.push({ y, label: val.toLocaleString() });
    }

    // Threat markers from alerts with timestamp_epoch
    const tMarkers = [];
    for (const a of alerts.slice(0, 20)) {
      const alertTime = a.timestamp_epoch ? a.timestamp_epoch * 1000 : null;
      if (alertTime && alertTime >= startT && alertTime <= now) {
        tMarkers.push({ x: toX(alertTime), type: a.attack_type || 'Threat' });
      }
    }

    return { ppsPath: pp, ppsFillPath: pFill, bpsPath: bp, gridLines: gLines, threatMarkers: tMarkers };
  }, [trafficHistory, alerts, chartW, chartH]);

  // Time labels for x-axis
  const timeLabels = useMemo(() => {
    const labels = [];
    for (let s = 0; s <= 60; s += 15) {
      const x = PAD_L + (s / 60) * chartW;
      labels.push({ x, label: s === 0 ? '-60s' : s === 60 ? 'Now' : `-${60 - s}s` });
    }
    return labels;
  }, [chartW]);


  return (
    <div className="bg-[#121720] border border-[#202735] rounded-[16px] p-4 flex flex-col justify-between relative overflow-hidden h-full min-h-[260px]">
      {/* Card Header */}
      <div className="flex items-center justify-between z-10 flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-[#F4F7FB]">Live Network Traffic</h3>
            <span className="px-1.5 py-0.5 text-[9px] font-mono text-[#62E8F7] bg-[#62E8F7]/10 rounded border border-[#62E8F7]/20">
              TIME SERIES
            </span>
          </div>
          <p className="text-[11px] text-[#667085] mt-0.5">
            Real-time throughput over the last 60 seconds.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-3 mr-2">
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-[#62E8F7]" />
              <span className="text-[9px] font-mono text-[#9AA4B2]">PPS</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-[#A78BFA]" />
              <span className="text-[9px] font-mono text-[#9AA4B2]">BPS</span>
            </div>
            {threatMarkers.length > 0 && (
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-sm bg-[#FF3B5C]" />
                <span className="text-[9px] font-mono text-[#9AA4B2]">THREAT</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[#161B25] border border-[#202735] rounded-full text-[11px] font-mono text-[#62E8F7]">
            <Radio className={`w-3 h-3 ${isMonitoring ? 'animate-pulse text-[#35D07F]' : 'text-[#667085]'}`} />
            <span>{isMonitoring ? 'LIVE LINK' : 'OFFLINE'}</span>
          </div>
        </div>
      </div>

      {/* SVG Time-Series Chart */}
      <div className="flex-1 relative mt-2 min-h-0">
        <div className="absolute inset-0 bg-[radial-gradient(#202735_1px,transparent_1px)] [background-size:14px_14px] opacity-30 pointer-events-none" />

        {trafficHistory.length < 2 ? (
          <div className="flex items-center justify-center h-full text-[#667085] text-xs font-mono">
            {isMonitoring
              ? 'Collecting traffic data...'
              : 'Start monitoring to see live throughput'}
          </div>
        ) : (
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full" preserveAspectRatio="none">
            {/* Horizontal grid lines */}
            {gridLines.map((g, i) => (
              <g key={i}>
                <line x1={PAD_L} x2={W - PAD_R} y1={g.y} y2={g.y} stroke="#202735" strokeWidth="0.5" strokeDasharray="4 3" />
                <text x={W - PAD_R - 2} y={g.y - 3} textAnchor="end" className="fill-[#667085]" fontSize="7" fontFamily="monospace">
                  {g.label}
                </text>
              </g>
            ))}

            {/* Time labels */}
            {timeLabels.map((tl, i) => (
              <text key={i} x={tl.x} y={H - 4} textAnchor="middle" className="fill-[#667085]" fontSize="7" fontFamily="monospace">
                {tl.label}
              </text>
            ))}

            {/* PPS fill area */}
            {ppsFillPath && (
              <path d={ppsFillPath} fill="url(#ppsGrad)" opacity="0.25" />
            )}

            {/* PPS line */}
            {ppsPath && (
              <path d={ppsPath} fill="none" stroke="#62E8F7" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            )}

            {/* BPS line */}
            {bpsPath && (
              <path d={bpsPath} fill="none" stroke="#A78BFA" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" strokeDasharray="3 2" opacity="0.7" />
            )}

            {/* Threat markers */}
            {threatMarkers.map((tm, i) => (
              <g key={i}>
                <line x1={tm.x} x2={tm.x} y1={PAD_T} y2={PAD_T + chartH} stroke="#FF3B5C" strokeWidth="1" strokeDasharray="2 2" opacity="0.6" />
                <circle cx={tm.x} cy={PAD_T + 6} r="3" fill="#FF3B5C" stroke="#0E131C" strokeWidth="1" />
              </g>
            ))}

            <defs>
              <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#62E8F7" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#62E8F7" stopOpacity="0.02" />
              </linearGradient>
            </defs>
          </svg>
        )}
      </div>

      {/* Bottom Stats Strip */}
      <div className="flex items-center justify-between mt-2 flex-shrink-0">
        <div className="bg-[#070B12]/90 border border-[#202735] rounded-lg px-2.5 py-1.5 backdrop-blur-md text-[11px] font-mono flex items-center gap-3">
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
          <div className="h-5 w-[1px] bg-[#202735]" />
          <div>
            <div className="text-[9px] text-[#667085] uppercase">TCP / UDP</div>
            <div className="font-bold text-[#F4F7FB]">
              <span className="text-[#60A5FA]">{stats.tcp_count || 0}</span>{' / '}
              <span className="text-[#A78BFA]">{stats.udp_count || 0}</span>
            </div>
          </div>
        </div>

        {alerts.length > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-lg text-[10px] font-mono text-[#FF5C6C]">
            <ShieldAlert className="w-3 h-3" />
            <span>{alerts.length} threats detected</span>
          </div>
        )}
      </div>
    </div>
  );
}
