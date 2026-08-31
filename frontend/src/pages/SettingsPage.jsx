import React from 'react';
import {
  Cpu,
  Wifi,
  Sliders,
} from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function SettingsPage() {
  const {
    interfaces,
    selectedInterface,
    setSelectedInterface,
    selectedMode,
    setSelectedMode,
    isMonitoring,
    activeMode,
    activeInterface,
    modelInfo,
  } = useMonitoring();

  return (
    <div className="h-full flex flex-col space-y-4 max-h-full overflow-y-auto pr-1">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-[#202735] flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#F4F7FB]">System Settings</h1>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#62E8F7]/15 text-[#62E8F7] border border-[#62E8F7]/30">
              Configuration
            </span>
          </div>
          <p className="text-xs text-[#9AA4B2] mt-0.5">
            Manage capture interfaces, intrusion detection policies, and ML pipeline parameters.
          </p>
        </div>
      </div>

      {/* Settings Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Network Interface Card */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F4F7FB]">
            <Wifi className="w-4 h-4 text-[#62E8F7]" />
            Network Capture Interface
          </div>
          <p className="text-xs text-[#9AA4B2]">
            Select the physical network adapter to capture line-rate frames using the Direct Npcap C-Types engine.
          </p>

          <div className="space-y-2 pt-1">
            <label className="text-[11px] font-mono text-[#667085] uppercase block">Selected Interface</label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isMonitoring}
              className="w-full bg-[#161B25] border border-[#202735] rounded-lg p-2 text-xs text-[#F4F7FB] focus:outline-none focus:border-[#62E8F7]/50 disabled:opacity-60"
            >
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} ({iface.ip}) {iface.status === 'UP' ? '● UP' : '○ DOWN'}
                </option>
              ))}
            </select>
          </div>

          <div className="text-[11px] text-[#667085] font-mono">
            Status:{' '}
            <span className={isMonitoring ? 'text-[#35D07F]' : 'text-[#9AA4B2]'}>
              {isMonitoring
                ? `Active [${activeMode}] on ${activeInterface || selectedInterface}`
                : 'Engine idle'}
            </span>
          </div>

        </div>

        {/* Capture Mode Card */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F4F7FB]">
            <Sliders className="w-4 h-4 text-[#A78BFA]" />
            Capture Mode Policy
          </div>
          <p className="text-xs text-[#9AA4B2]">
            Choose between physical packet interception and synthetic traffic stream replay.
          </p>

          <div className="grid grid-cols-2 gap-2 pt-1">
            <button
              onClick={() => setSelectedMode('LIVE')}
              disabled={isMonitoring}
              className={`p-3 rounded-xl border text-left transition-all ${
                selectedMode === 'LIVE'
                  ? 'bg-[#62E8F7]/15 border-[#62E8F7]/40 text-[#F4F7FB]'
                  : 'bg-[#161B25] border-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB]'
              }`}
            >
              <div className="font-semibold text-xs text-[#62E8F7]">Direct Npcap Live</div>
              <div className="text-[10px] text-[#667085] mt-1">32MB kernel buffer wire capture</div>
            </button>

            <button
              onClick={() => setSelectedMode('SIMULATION')}
              disabled={isMonitoring}
              className={`p-3 rounded-xl border text-left transition-all ${
                selectedMode === 'SIMULATION'
                  ? 'bg-[#FFC043]/15 border-[#FFC043]/40 text-[#FFC043]'
                  : 'bg-[#161B25] border-[#202735] text-[#9AA4B2] hover:text-[#F4F7FB]'
              }`}
            >
              <div className="font-semibold text-xs text-[#FFC043]">Simulation Mode</div>
              <div className="text-[10px] text-[#667085] mt-1">Generates simulated packets</div>
            </button>
          </div>
        </div>

        {/* ML Model Specifications Card */}
        <div className="bg-[#121720] border border-[#202735] rounded-xl p-4 space-y-3 md:col-span-2">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F4F7FB]">
            <Cpu className="w-4 h-4 text-[#35D07F]" />
            Intrusion Detection Model Specifications
          </div>
          <p className="text-xs text-[#9AA4B2]">
            Detailed metrics and hyperparameter schema for the trained machine learning classifier.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="p-3 bg-[#161B25] border border-[#202735] rounded-lg">
              <div className="text-[10px] font-mono text-[#667085] uppercase">Algorithm</div>
              <div className="text-sm font-bold text-[#F4F7FB] mt-0.5">
                {modelInfo?.model_type || 'XGBoost GPU/CPU'}
              </div>
            </div>

            <div className="p-3 bg-[#161B25] border border-[#202735] rounded-lg">
              <div className="text-[10px] font-mono text-[#667085] uppercase">Feature Vector</div>
              <div className="text-sm font-bold text-[#62E8F7] mt-0.5">
                {modelInfo?.feature_count || 70} CICIDS2017 Columns
              </div>
            </div>

            <div className="p-3 bg-[#161B25] border border-[#202735] rounded-lg">
              <div className="text-[10px] font-mono text-[#667085] uppercase">Training Dataset</div>
              <div className="text-sm font-bold text-[#A78BFA] mt-0.5">
                {modelInfo?.dataset || 'CICIDS2017 Clean'}
              </div>
            </div>

            <div className="p-3 bg-[#161B25] border border-[#202735] rounded-lg">
              <div className="text-[10px] font-mono text-[#667085] uppercase">Benchmark Accuracy</div>
              <div className="text-sm font-bold text-[#35D07F] mt-0.5">
                {modelInfo?.accuracy ? `${modelInfo.accuracy}%` : '99.91%'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
