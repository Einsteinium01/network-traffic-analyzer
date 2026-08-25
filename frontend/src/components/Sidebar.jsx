import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  GitBranch,
  ChartNoAxesCombined,
  FileText,
  Settings,
  HelpCircle,
  Server,
  Shield,
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navGroups = [
    {
      group: 'OVERVIEW',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'live-traffic', label: 'Live Traffic', icon: Activity },
      ],
    },
    {
      group: 'SECURITY',
      items: [
        { id: 'threats', label: 'Threats', icon: ShieldAlert, badge: '27' },
        { id: 'flows', label: 'Network Flows', icon: GitBranch },
        { id: 'analytics', label: 'Analytics', icon: ChartNoAxesCombined },
      ],
    },
    {
      group: 'SYSTEM',
      items: [
        { id: 'logs', label: 'Logs', icon: FileText },
        { id: 'settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <aside className="w-[248px] h-screen bg-[#070B12] border-r border-[#151B24] flex flex-col fixed left-0 top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#151B24]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#62E8F7] to-[#A78BFA] p-[1px] flex items-center justify-center glow-cyan">
            <div className="w-full h-full bg-[#070B12] rounded-[7px] flex items-center justify-center">
              <Shield className="w-4 h-4 text-[#62E8F7]" />
            </div>
          </div>
          <div>
            <div className="text-base font-bold tracking-tight text-[#F4F7FB] flex items-center gap-1.5">
              NetIntel
            </div>
            <div className="text-[10px] font-medium tracking-[0.08em] text-[#667085] uppercase">
              NETWORK INTELLIGENCE
            </div>
          </div>
        </div>
      </div>

      {/* Main Navigation Groups */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {navGroups.map((group) => (
          <div key={group.group}>
            <div className="px-3 mb-2 text-[10px] font-medium tracking-[0.08em] text-[#667085] uppercase">
              {group.group}
            </div>
            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2.5 rounded-[10px] text-sm font-medium transition-all duration-150 ${
                      isActive
                        ? 'nav-active-gradient text-[#F4F7FB]'
                        : 'text-[#9AA4B2] hover:bg-[#121720] hover:text-[#F4F7FB]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon
                        className={`w-4 h-4 transition-colors ${
                          isActive ? 'text-[#62E8F7]' : 'text-[#667085]'
                        }`}
                      />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-[#FF3B5C]/15 text-[#FF5C6C] rounded-md border border-[#FF3B5C]/30">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Sidebar Footer */}
      <div className="p-3 border-t border-[#151B24] space-y-1 bg-[#05080E]">
        <button
          onClick={() => setActiveTab('support')}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-[10px] text-xs text-[#9AA4B2] hover:bg-[#121720] hover:text-[#F4F7FB] transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5 text-[#667085]" />
          <span>Support</span>
        </button>

        <div className="flex items-center justify-between px-3 py-2 text-xs text-[#667085]">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-[#35D07F]" />
            <span>Engine Active</span>
          </div>
          <span className="text-[10px] font-mono text-[#667085]">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}
