import { invoke } from '@tauri-apps/api/core';
import { 
  Alert, 
  TrafficData, 
  TrafficHistoryDataPoint, 
  DashboardData,
  PaginatedAlertsResponse 
} from './api';

/**
 * Tauri-based API service that uses invoke commands instead of HTTP requests
 */
class TauriApiService {
  
  async get<T>(endpoint: string): Promise<T> {
    try {
      const result = await invoke('api_request', { endpoint });
      return result as T;
    } catch (error) {
      console.error(`Tauri API request failed for ${endpoint}:`, error);
      throw new Error(`Failed to fetch data from ${endpoint}: ${error}`);
    }
  }

  async post<T>(_endpoint: string, _data: any = {}): Promise<T> {
    // For now, we'll implement GET requests only
    // POST requests would need a separate Tauri command
    throw new Error('POST requests not implemented yet in Tauri API service');
  }

  async put<T>(_endpoint: string, _data: any = {}): Promise<T> {
    // For now, we'll implement GET requests only
    // PUT requests would need a separate Tauri command
    throw new Error('PUT requests not implemented yet in Tauri API service');
  }

  async delete<T>(_endpoint: string): Promise<T> {
    // For now, we'll implement GET requests only
    // DELETE requests would need a separate Tauri command
    throw new Error('DELETE requests not implemented yet in Tauri API service');
  }
}

// Create instance
const tauriApi = new TauriApiService();

// Export the same interface as the HTTP API service
export const dashboardApi = {
  getDashboardData: (): Promise<DashboardData> => tauriApi.get('/api/v1/dashboard'),
  getSystemStats: (): Promise<any> => tauriApi.get('/api/v1/dashboard/stats'),
  getRecentAlerts: (): Promise<Alert[]> => tauriApi.get('/api/v1/dashboard/alerts/recent'),
  getTrafficData: async (): Promise<TrafficData> => {
    const response = await tauriApi.get<any>('/api/v1/dashboard/traffic');
    if (response && response.current) {
      return {
        inbound: response.current.inbound_mbps || 0,
        outbound: response.current.outbound_mbps || 0,
        blockedConnections: response.current.blocked_connections || 0,
        threatsBlockedToday: response.current.threats_blocked_today || 0,
      };
    } else {
      console.warn('Unexpected structure for traffic data:', response);
      return {
        inbound: 0,
        outbound: 0,
        blockedConnections: 0,
        threatsBlockedToday: 0,
      };
    }
  },
  getTrafficHistory: (): Promise<TrafficHistoryDataPoint[]> => tauriApi.get('/api/v1/dashboard/traffic/history'),
};

export const alertsApi = {
  getAlerts: (_params: any = {}): Promise<PaginatedAlertsResponse> => {
    // For now, ignore params and just get all alerts
    return tauriApi.get('/api/v1/alerts');
  },
  getAlertStats: (): Promise<{ unreadCount: number; totalCount: number; highPriorityCount: number; }> => tauriApi.get('/api/v1/alerts/stats'),
  // Add other methods as needed
};

export const settingsApi = {
  getGeneralSettings: () => tauriApi.get('/api/v1/settings'),
  getDetectionSettings: () => tauriApi.get('/api/v1/settings/detection'),
  getNetworkSettings: () => tauriApi.get('/api/v1/settings/network'),
  getNotificationSettings: () => tauriApi.get('/api/v1/settings/notification'),
  // Add other methods as needed
};

export const systemApi = {
  getSystemInfo: () => tauriApi.get('/api/v1/system/info'),
  getSystemLogs: (_params = {}) => tauriApi.get('/api/v1/system/logs'),
  // Add other methods as needed
};

export const reportsApi = {
  getReports: () => tauriApi.get('/api/v1/reports'),
  getFsReports: () => tauriApi.get('/api/v1/reports/fs'),
  // Add other methods as needed
};

export const preventionApi = {
  getPreventionSettings: () => tauriApi.get('/api/v1/prevention/settings'),
  getBlockedIps: () => tauriApi.get('/api/v1/prevention/blocked'),
  // Add other methods as needed
};

export const faqApi = {
  getFaqItems: () => tauriApi.get('/api/v1/faq'),
};

export const checkHealth = () => tauriApi.get('/health'); 