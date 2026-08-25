import React from 'react';
import { Search, Bell, SlidersHorizontal, User, Wifi, Cpu, AlertTriangle } from 'lucide-react';
import { useMonitoring } from '../context/MonitoringContext';

export default function TopBar() {
  const {
    isMonitoring,
    captureMode,
    setCaptureMode,
    selectedInterface,
    setSelectedInterface,
    interfaces,
    toggleMonitoring,
    startMonitoringMode,
    isLoading,
    error,
  } = useMonitoring();

  const handleInterfaceChange = (e) => {
    const newIface = e.target.value;
    setSelectedInterface(newIface);
    if (isMonitoring) {
      startMonitoringMode(captureMode, newIface);
    }
  };

  const handleModeToggle = (newMode) => {
    setCaptureMode(newMode);
    if (isMonitoring) {
      startMonitoringMode(newMode, selectedInterface);
    }
  };

  return (
    <header className="h-14 border-b border-[#202735] bg-[#090D13]/80 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between px-5">
      {/* Left: Search Input & Error Indicator */}
      <div className="flex items-center gap-3">
        <div className="relative w-64">
          <Search className="w-3.5 h-3.5 text-[#667085] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="SEARCH NETWORK..."
            className="w-full bg-[#121720] border border-[#202735] focus:border-[#62E8F7]/50 focus:outline-none rounded-xl py-1.5 pl-9 pr-3 text-[11px] tracking-wider text-[#F4F7FB] placeholder-[#667085] transition-all"
          />
        </div>

        {/* Explicit Backend Error Banner */}
        {error && (
          <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-xl bg-[#FF5C6C]/10 border border-[#FF5C6C]/30 text-[#FF5C6C] text-[11px] animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="truncate max-w-xs">{error}</span>
          </div>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Interface Selector Dropdown */}
        <div className="flex items-center gap-1.5 bg-[#121720] border border-[#202735] rounded-xl px-2.5 py-1 text-[11px] text-[#F4F7FB]">
          <Wifi className="w-3.5 h-3.5 text-[#62E8F7]" />
          <select
            value={selectedInterface}
            onChange={handleInterfaceChange}
            disabled={isLoading}
            className="bg-transparent focus:outline-none text-[11px] text-[#F4F7FB] font-medium cursor-pointer"
          >
            {interfaces.length === 0 ? (
              <option value="" className="bg-[#121720] text-[#F4F7FB]">Auto / Default</option>
            ) : (
              interfaces.map((iface) => (
                <option key={iface.name} value={iface.name} className="bg-[#121720] text-[#F4F7FB]">
                  {iface.name} ({iface.ip}) {iface.status === 'UP' ? '●' : ''}
                </option>
              ))
            )}
          </select>
        </div>

        {/* Mode Selector Switch (LIVE vs SIMULATION) */}
        <div className="flex items-center bg-[#121720] border border-[#202735] rounded-xl p-0.5 text-[10px] font-semibold">
          <button
            onClick={() => handleModeToggle('LIVE')}
            className={`px-2.5 py-1 rounded-lg transition-all flex items-center gap-1 ${
              captureMode === 'LIVE'
                ? 'bg-[#62E8F7]/20 text-[#62E8F7] border border-[#62E8F7]/40 shadow-sm'
                : 'text-[#667085] hover:text-[#F4F7FB]'
            }`}
          >
            <Wifi className="w-3 h-3" />
            LIVE
          </button>
          <button
            onClick={() => handleModeToggle('SIMULATION')}
            className={`px-2.5 py-1 rounded-lg transition-all flex items-center gap-1 ${
              captureMode === 'SIMULATION'
                ? 'bg-[#FFC043]/20 text-[#FFC043] border border-[#FFC043]/40 shadow-sm'
                : 'text-[#667085] hover:text-[#F4F7FB]'
            }`}
          >
            <Cpu className="w-3 h-3" />
            SIM
          </button>
        </div>

        {/* Global Status Badge (TASK 9) */}
        <button
          onClick={toggleMonitoring}
          disabled={isLoading}
          className={`px-3 py-1 rounded-full border text-[11px] font-semibold flex items-center gap-2 transition-all ${
            isMonitoring
              ? captureMode === 'LIVE'
                ? 'bg-[#35D07F]/10 border-[#35D07F]/40 text-[#35D07F] shadow-[0_0_12px_rgba(53,208,127,0.2)]'
                : 'bg-[#FFC043]/10 border-[#FFC043]/40 text-[#FFC043]'
              : 'bg-[#121720] border-[#202735] text-[#9AA4B2] hover:border-[#303A4A]'
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isMonitoring
                ? captureMode === 'LIVE'
                  ? 'bg-[#35D07F] animate-pulse'
                  : 'bg-[#FFC043]'
                : 'bg-[#667085]'
            }`}
          />
          <span>
            {isLoading
              ? 'Connecting...'
              : isMonitoring
              ? captureMode === 'LIVE'
                ? `● LIVE CAPTURE [${selectedInterface || 'Auto'}]`
                : '○ SIMULATION [Synthetic traffic]'
              : '○ MONITORING OFF'}
          </span>
        </button>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 border-l border-[#202735]">
          <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-[#161B25] to-[#202735] border border-[#303A4A] flex items-center justify-center text-[#62E8F7]">
            <User className="w-3.5 h-3.5" />
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-[11px] font-semibold text-[#F4F7FB]">Security Admin</div>
            <div className="text-[9px] text-[#667085]">SOC Analyst</div>
          </div>
        </div>
      </div>
    </header>
  );
}

