import React from 'react';

export default function CircularMetric({ label, value, subtext, percentage = 75, color = 'cyan' }) {
  const strokeColors = {
    cyan: '#62E8F7',
    purple: '#A78BFA',
    magenta: '#EC5BCB',
  };

  const currentColor = strokeColors[color] || strokeColors.cyan;
  const radius = 28;
  const strokeWidth = 4;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className="bg-[#121720] border border-[#202735] hover:border-[#303A4A] rounded-[14px] p-3 flex items-center gap-3.5 transition-all">
      {/* SVG Ring */}
      <div className="relative w-14 h-14 flex-shrink-0 flex items-center justify-center">
        <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
          <circle
            stroke="#1C2432"
            fill="transparent"
            strokeWidth={strokeWidth}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
          />
          <circle
            stroke={currentColor}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference + ' ' + circumference}
            style={{ strokeDashoffset }}
            strokeLinecap="round"
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            className="transition-all duration-500 ease-out"
          />
        </svg>
        <div className="absolute text-center">
          <span className="text-xs font-bold text-[#F4F7FB] font-mono">{value}</span>
        </div>
      </div>

      {/* Label & Details */}
      <div className="min-w-0">
        <div className="text-[10px] font-medium tracking-[0.08em] text-[#9AA4B2] uppercase truncate">
          {label}
        </div>
        <div className="text-[11px] text-[#667085] mt-0.5 truncate">{subtext}</div>
      </div>
    </div>
  );
}
