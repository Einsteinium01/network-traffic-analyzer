import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 5000,
});

export const apiService = {
  // Fetch available network interfaces
  async getInterfaces() {
    const response = await apiClient.get('/interfaces');
    return response.data;
  },

  // Start packet capture & detection engine
  async startMonitoring(mode = 'LIVE', interfaceName = null) {
    const response = await apiClient.post('/start', { mode, interface: interfaceName });
    return response.data;
  },

  // Stop capture engine
  async stopMonitoring() {
    const response = await apiClient.post('/stop');
    return response.data;
  },

  // Get live engine status and metrics DTO
  async getStatus() {
    const response = await apiClient.get('/status');
    return response.data;
  },

  // Get recent threat alerts
  async getAlerts(limit = 50) {
    const response = await apiClient.get('/alerts', { params: { limit } });
    return response.data;
  },

  // Get recent packet logs
  async getLogs(limit = 50) {
    const response = await apiClient.get('/logs', { params: { limit } });
    return response.data;
  },
};

export default apiService;
