import React, { useState } from 'react';
import { MonitoringProvider } from './context/MonitoringContext';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import DashboardPage from './pages/DashboardPage';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <MonitoringProvider>
      <div className="h-screen w-screen bg-[#090D13] text-[#F4F7FB] flex overflow-hidden antialiased">
        {/* Fixed Left Sidebar (248px) */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Main Viewport Container */}
        <div className="flex-1 ml-[248px] flex flex-col h-full min-w-0 overflow-hidden">
          {/* Sticky TopBar */}
          <TopBar />

          {/* Dashboard Main Content Canvas */}
          <main className="flex-1 p-4 lg:p-5 overflow-hidden flex flex-col min-h-0">
            {activeTab === 'dashboard' ? (
              <DashboardPage />
            ) : (
              <div className="bg-[#121720] border border-[#202735] rounded-[16px] p-8 text-center my-auto max-w-lg mx-auto">
                <h2 className="text-xl font-bold text-[#F4F7FB] capitalize">
                  {activeTab.replace('-', ' ')} Module
                </h2>
                <p className="text-xs text-[#9AA4B2] mt-2 leading-relaxed">
                  The application shell and dashboard composition are active. This section view will be connected in subsequent steps.
                </p>
                <button
                  onClick={() => setActiveTab('dashboard')}
                  className="mt-6 px-4 py-2 bg-[#161B25] border border-[#303A4A] rounded-xl text-xs font-semibold text-[#62E8F7] hover:bg-[#202735] transition-all"
                >
                  Return to Dashboard Overview
                </button>
              </div>
            )}
          </main>
        </div>
      </div>
    </MonitoringProvider>
  );
}
