import React from 'react';

export default function KpiCard({ label, value, supporting, icon: Icon, iconTint }) {
  // Tint styling mapping per design.md section 16
  const tintStyles = {
    cyan: 'bg-[#62E8F7]/10 text-[#62E8F7] border-[#62E8F7]/20',
    blue: 'bg-[#60A5FA]/10 text-[#60A5FA] border-[#60A5FA]/20',
    magenta: 'bg-[#EC5BCB]/10 text-[#EC5BCB] border-[#EC5BCB]/20',
    green: 'bg-[#35D07F]/10 text-[#35D07F] border-[#35D07F]/20',
  };

  const currentTint = tintStyles[iconTint] || tintStyles.cyan;

  return (
    <div className="bg-[#121720] border border-[#202735] hover:border-[#303A4A] rounded-[14px] p-3.5 transition-all duration-200 group flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div>
          <span className="text-[10px] font-medium tracking-[0.08em] text-[#9AA4B2] uppercase">
            {label}
          </span>
          <div className="text-xl lg:text-2xl font-bold tracking-tight text-[#F4F7FB] mt-0.5 font-mono">
            {value}
          </div>
        </div>

        {Icon && (
          <div
            className={`w-9 h-9 rounded-[10px] border flex items-center justify-center transition-transform group-hover:scale-105 ${currentTint}`}
          >
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="mt-2 pt-2 border-t border-[#1C2432] text-[11px] text-[#667085] flex items-center gap-1">
        <span className="truncate">{supporting}</span>
      </div>
    </div>
  );
}
