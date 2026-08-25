import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import apiService from '../services/api';
import socketService from '../services/socket';

const MonitoringContext = createContext(null);

export function MonitoringProvider({ children }) {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [captureMode, setCaptureMode] = useState('LIVE');
  const [selectedInterface, setSelectedInterface] = useState('');
  const [interfaces, setInterfaces] = useState([]);
  const [stats, setStats] = useState({
    total_packets: 0,
    total_bytes: 0,
    normal_packets: 0,
    attack_packets: 0,
    threat_level: 'LOW',
    normal_pct: 100.0,
    attack_pct: 0.0,
    packets_per_second: 0.0,
    bytes_per_second: 0.0,
    active_flows: 0,
    duration_seconds: 0.0,
  });
  const [recentPackets, setRecentPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([
    {
      id: 'init-1',
      title: 'Engine Ready',
      desc: 'Intelligent Network Traffic Analyzer connected',
      time: 'Just now',
      type: 'normal',
    },
  ]);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Packet batching buffer
  const packetBufferRef = useRef([]);
  const alertBufferRef = useRef([]);

  // Fetch available network interfaces from backend
  const fetchInterfaces = useCallback(async () => {
    try {
      const data = await apiService.getInterfaces();
      const list = data.interfaces || [];
      setInterfaces(list);

      // Auto-select first active UP non-loopback interface if not set
      if (!selectedInterface && list.length > 0) {
        const activeUp = list.find((i) => i.status === 'UP' && !i.is_loopback);
        if (activeUp) {
          setSelectedInterface(activeUp.name);
        } else {
          setSelectedInterface(list[0].name);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch network interfaces:', err.message);
    }
  }, [selectedInterface]);

  // Fetch live status from backend
  const fetchStatus = useCallback(async () => {
    try {
      const data = await apiService.getStatus();
      setIsMonitoring(Boolean(data.is_running));
      if (data.capture_mode) setCaptureMode(data.capture_mode);
      if (data.interface) setSelectedInterface(data.interface);
      if (data.error_message) setError(data.error_message);
      setStats((prev) => ({ ...prev, ...data }));
    } catch (err) {
      console.warn('Backend offline:', err.message);
    }
  }, []);

  // Fetch initial state on mount
  useEffect(() => {
    fetchInterfaces();
    fetchStatus();
    const statusInterval = setInterval(fetchStatus, 2000);
    return () => clearInterval(statusInterval);
  }, [fetchStatus, fetchInterfaces]);

  // Connect Socket.IO & handle live streaming events
  useEffect(() => {
    socketService.connect();

    const handlePacket = (packet) => {
      packetBufferRef.current.push(packet);
    };

    const handleAlert = (alertPkt) => {
      alertBufferRef.current.push(alertPkt);
    };

    const handleStatus = (statusData) => {
      setIsMonitoring(Boolean(statusData.is_running));
      if (statusData.capture_mode) setCaptureMode(statusData.capture_mode);
      if (statusData.interface) setSelectedInterface(statusData.interface);
      setStats((prev) => ({ ...prev, ...statusData }));
    };

    socketService.on('packet', handlePacket);
    socketService.on('alert', handleAlert);
    socketService.on('status', handleStatus);

    // Batch UI updates every 300ms for packet and alert feeds
    const batchInterval = setInterval(() => {
      if (packetBufferRef.current.length > 0) {
        const newPackets = [...packetBufferRef.current];
        packetBufferRef.current = [];

        setRecentPackets((prev) => {
          const combined = [...newPackets, ...prev];
          return combined.slice(0, 100);
        });
      }

      if (alertBufferRef.current.length > 0) {
        const newAlerts = [...alertBufferRef.current];
        alertBufferRef.current = [];

        setAlerts((prev) => [...newAlerts, ...prev].slice(0, 50));

        // Append to timeline security events
        const newEvents = newAlerts.map((a) => ({
          id: a.id || `alert-${Date.now()}-${Math.random()}`,
          title: `Threat: ${a.attack_type || 'Malicious Activity'}`,
          desc: `Attack detected from ${a.src_ip} -> ${a.dst_ip} (${a.confidence_pct}% conf)`,
          time: 'Just now',
          type: 'attack',
        }));

        setSecurityEvents((prev) => [...newEvents, ...prev].slice(0, 20));
      }
    }, 300);

    return () => {
      clearInterval(batchInterval);
      socketService.off('packet', handlePacket);
      socketService.off('alert', handleAlert);
      socketService.off('status', handleStatus);
    };
  }, []);

  // Start monitoring with specified mode & interface
  const startMonitoringMode = async (requestedMode = captureMode, targetInterface = selectedInterface) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiService.startMonitoring(requestedMode, targetInterface);
      setIsMonitoring(true);
      if (res.capture_mode) setCaptureMode(res.capture_mode);
      if (res.interface) setSelectedInterface(res.interface);

      setSecurityEvents((prev) => [
        {
          id: `start-${Date.now()}`,
          title: `Monitoring Started (${res.capture_mode || requestedMode})`,
          desc: `Capturing on interface: ${res.interface || targetInterface || 'Auto'}`,
          time: 'Just now',
          type: 'normal',
        },
        ...prev,
      ]);
      await fetchStatus();
    } catch (err) {
      console.error('Failed to start monitoring:', err);
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to start packet capture';
      setError(msg);
      setIsMonitoring(false);
    } finally {
      setIsLoading(false);
    }
  };

  // Stop monitoring action
  const stopMonitoringMode = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await apiService.stopMonitoring();
      setIsMonitoring(false);
      setSecurityEvents((prev) => [
        {
          id: `stop-${Date.now()}`,
          title: 'Monitoring Stopped',
          desc: 'Packet capture paused by operator',
          time: 'Just now',
          type: 'warning',
        },
        ...prev,
      ]);
      await fetchStatus();
    } catch (err) {
      console.error('Failed to stop monitoring:', err);
      setError(err.response?.data?.error || 'Failed to stop monitoring');
    } finally {
      setIsLoading(false);
    }
  };

  // Toggle monitoring button handler
  const toggleMonitoring = async () => {
    if (isMonitoring) {
      await stopMonitoringMode();
    } else {
      await startMonitoringMode(captureMode, selectedInterface);
    }
  };

  const value = {
    isMonitoring,
    captureMode,
    setCaptureMode,
    selectedInterface,
    setSelectedInterface,
    interfaces,
    stats,
    recentPackets,
    alerts,
    securityEvents,
    error,
    isLoading,
    startMonitoringMode,
    stopMonitoringMode,
    toggleMonitoring,
    fetchStatus,
    fetchInterfaces,
  };

  return <MonitoringContext.Provider value={value}>{children}</MonitoringContext.Provider>;
}

export function useMonitoring() {
  const context = useContext(MonitoringContext);
  if (!context) {
    throw new Error('useMonitoring must be used within a MonitoringProvider');
  }
  return context;
}
