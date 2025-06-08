import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

// Define types for our API responses
export interface Alert {
  id?: string;
  alert_id?: string;
  _id?: any;
  timestamp: string | { $date: { $numberLong: string } };
  severity: 'High' | 'Medium' | 'Low' | string;
  description: string;
  source_ip?: string;
  destination_ip?: string;
  protocol?: string;
  status?: 'read' | 'unread' | string;
}

export interface TrafficData {
  inbound: number;
  outbound: number;
  blockedConnections: number;
  threatsBlockedToday: number;
}

export interface SystemInfo {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  uptime: string;
}

export interface DashboardData {
  system_status: string;
  security_score: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  alert_summary: AlertStatsSummary;
  traffic_stats: TrafficStats;
  system_health: SystemHealth;
  recent_alerts: Alert[];
}

export interface Report {
  report_id: string;
  title: string;
  report_type: string;
  status: 'Completed' | 'Processing' | 'Failed' | 'Pending' | 'InProgress';
  format: 'pdf' | 'csv' | 'json' | 'html';
  generated_at: string;
  file_path?: string;
}

export interface FsReportInfo {
  file_name: string;
  file_path: string;
  report_type: string;
  format: string;
  generated_at: string;
  file_size: number;
}

export interface ReportGenerationParams {
  report_type: string;
  format: string;
  title?: string;
  period_start?: string;
  period_end?: string;
}

export interface TrafficHistoryDataPoint {
  timestamp: string; // Or Date
  value: number; // e.g., Mbps or connection count for the period
}

// Settings Types
export interface GeneralSettings {
  emailNotifications: boolean;
  dataRetentionDays: number; 
}

export interface DetectionSettings {
  detectionSensitivity: string; 
}

export interface NetworkSettings {
  [key: string]: any; 
}

export interface NotificationSettings {
  [key: string]: any;
}

// Prevention Types
export interface PreventionSettings {
  [key: string]: any;
}

export interface BlockedIp {
  ip: string;
  reason: string;
  timestamp: string; // Or Date
}

// FAQ Type
export interface FAQItem {
  id: string; 
  question: string;
  answer: string;
  category: string;
  lastUpdated?: string;
}

// Add new interface for paginated alerts response
export interface PaginatedAlertsResponse {
  alerts: Alert[];
  page: number;
  limit: number;
  total: number;
  total_pages: number;
  // Add any other pagination fields if present in the actual API response
}

// New interfaces matching Rust structs from src-tauri/src/api/handlers/dashboard.rs

export interface SystemHealth {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  uptime_seconds: number;
  last_scan: string;
}

export interface TrafficStats {
  inbound_mbps: number;
  outbound_mbps: number;
  traffic_by_protocol: Record<string, number>;
  active_connections: number;
  blocked_connections: number;
  threats_blocked_today: number;
}

// New interface for the structure returned by Rust's get_alert_stats
export interface AlertStatsSummary {
  unreadCount: number;
  totalCount: number;
  highPriorityCount: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>; // Assuming 'new', 'acknowledged' etc. are keys here
  recent_trend: {
    last_24h: number;
    last_7d: number;
    previous_7d: number;
    trend_percentage: number;
  };
}

/**
 * API service for making requests to the backend using Axios
 */
class ApiService {
  private axios: AxiosInstance;
  private baseUrl: string;

  constructor() {
    // Use the default host and port from config.rs
    const host = '127.0.0.1'; // Default from config.rs
    const port = '55035'; // Default from config.rs
    this.baseUrl = `http://${host}:${port}/api/v1`;

    // Create axios instance with default configs
    this.axios = axios.create({
      baseURL: this.baseUrl,
      timeout: 30000, // Increased timeout to 30 seconds for report generation
      headers: {
        'Content-Type': 'application/json',
      }
    });

    // Add response interceptor for error handling
    this.axios.interceptors.response.use(
      response => response.data,
      error => {
        let errorMessage = 'Unknown error occurred';
        
        if (error.code === 'ECONNABORTED') {
          // Handle timeout specifically
          errorMessage = 'Request timeout - server took too long to respond';
        } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
          // Handle connection refused or DNS errors
          errorMessage = 'No response received from server';
        } else if (error.response) {
          // Server responded with error status
          console.error(`API Error (${error.response.status}):`, error.response.data);
          
          if (error.response.status >= 500) {
            errorMessage = 'Server error - please try again later';
          } else if (error.response.status === 404) {
            errorMessage = 'Resource not found';
          } else if (error.response.status === 403) {
            errorMessage = 'Access denied';
          } else if (error.response.status === 401) {
            errorMessage = 'Authentication required';
          } else {
            errorMessage = error.response.data?.message || 
                          error.response.data?.error || 
                          `Request failed with status ${error.response.status}`;
          }
        } else if (error.request) {
          // Request was made but no response received
          console.error('API request failed - no response:', error.request);
          errorMessage = 'No response received from server';
        } else {
          // Error in setting up the request
          console.error('API request setup error:', error.message);
          errorMessage = error.message || 'Failed to send request';
        }
        
        return Promise.reject(new Error(errorMessage));
      }
    );
  }

  /**
   * Make a GET request to the API
   * @param {string} endpoint - The endpoint to request (without base URL)
   * @param {object} params - Query parameters
   * @returns {Promise<any>} - The response data
   */
  async get<T>(endpoint: string, params = {}): Promise<T> {
    try {
      const config: AxiosRequestConfig = { params };
      return await this.axios.get(endpoint, config);
    } catch (error) {
      console.error(`API GET request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  /**
   * Make a POST request to the API
   * @param {string} endpoint - The endpoint to request (without base URL)
   * @param {object} data - The data to send
   * @returns {Promise<any>} - The response data
   */
  async post<T>(endpoint: string, data = {}): Promise<T> {
    try {
      return await this.axios.post(endpoint, data);
    } catch (error) {
      console.error(`API POST request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  /**
   * Make a PUT request to the API
   * @param {string} endpoint - The endpoint to request (without base URL)
   * @param {object} data - The data to send
   * @returns {Promise<any>} - The response data
   */
  async put<T>(endpoint: string, data = {}): Promise<T> {
    try {
      return await this.axios.put(endpoint, data);
    } catch (error) {
      console.error(`API PUT request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  /**
   * Make a DELETE request to the API
   * @param {string} endpoint - The endpoint to request (without base URL)
   * @returns {Promise<any>} - The response data
   */
  async delete<T>(endpoint: string): Promise<T> {
    try {
      return await this.axios.delete(endpoint);
    } catch (error) {
      console.error(`API DELETE request failed for ${endpoint}:`, error);
      throw error;
    }
  }
}

// Export a singleton instance
export const api = new ApiService();

// Define API endpoints
export const endpoints = {
  // Dashboard
  dashboard: {
    data: '/dashboard',
    stats: '/dashboard/stats',
    recentAlerts: '/dashboard/alerts/recent',
    trafficData: '/dashboard/traffic',
    trafficHistory: '/dashboard/traffic/history',
  },
  
  // Alerts
  alerts: {
    list: '/alerts',
    detail: (id: number | string) => `/alerts/${id}`,
    resolve: (id: number | string) => `/alerts/${id}/resolve`,
    comment: (id: number | string) => `/alerts/${id}/comment`,
    updateStatus: (id: string) => `/alerts/${id}`,
    delete: (id: string) => `/alerts/${id}`,
    stats: '/alerts/stats',
    markAllRead: '/alerts/mark-all-read',
    markAllSystemRead: '/alerts/mark-all-system-read',
  },
  
  // Reports
  reports: {
    list: '/reports',
    fs: '/reports/fs',
    html: (filename: string) => `/reports/html/${filename}`,
    detail: (id: number | string) => `/reports/${id}`,
    download: (id: number | string) => `/reports/${id}/download`,
    generate: '/reports',
  },
  
  // Settings
  settings: {
    general: '/settings',
    detection: '/settings/detection',
    network: '/settings/network',
    notification: '/settings/notification',
    system: {
      info: '/system/info',
      logs: '/system/logs',
      restart: '/system/restart',
    },
  },
  
  // Prevention
  prevention: {
    settings: '/prevention/settings',
    blockedIps: '/prevention/blocked',
    block: '/prevention/block',
    unblock: (ip: string) => `/prevention/unblock/${ip}`,
  },
  
  // Health check
  health: '/health',
  faq: '/faq', // New endpoint for FAQ items
};

// Dashboard functions
export const dashboardApi = {
  getDashboardData: (): Promise<DashboardData> => api.get<DashboardData>(endpoints.dashboard.data),
  getSystemStats: (): Promise<any> => api.get<any>(endpoints.dashboard.stats), // Define specific stats type if known
  getRecentAlerts: (): Promise<Alert[]> => api.get<Alert[]>(endpoints.dashboard.recentAlerts),
  getTrafficData: async (): Promise<TrafficData> => {
    const response = await api.get<any>(endpoints.dashboard.trafficData); // Use any for the raw response type
    // Assuming the Rust handler now returns { current: { inbound_mbps: ..., outbound_mbps: ..., blocked_connections: ... } }
    if (response && response.current) {
      return {
        inbound: response.current.inbound_mbps || 0,
        outbound: response.current.outbound_mbps || 0,
        blockedConnections: response.current.blocked_connections || 0,
        threatsBlockedToday: response.current.threats_blocked_today || 0,
      };
    } else {
      // Fallback or error handling if the structure is not as expected
      console.warn('Unexpected structure for traffic data:', response);
      return {
        inbound: 0,
        outbound: 0,
        blockedConnections: 0,
        threatsBlockedToday: 0,
      };
    }
  },
  getTrafficHistory: (): Promise<TrafficHistoryDataPoint[]> => api.get<TrafficHistoryDataPoint[]>(endpoints.dashboard.trafficHistory),
};

// Alert functions
export const alertsApi = {
  getAlerts: (params: any = {}): Promise<PaginatedAlertsResponse> => api.get(endpoints.alerts.list, params),
  getAlertById: (id: string): Promise<Alert> => api.get(endpoints.alerts.detail(id)),
  createAlert: (alertData: Partial<Alert>): Promise<Alert> => api.post(endpoints.alerts.list, alertData),
  updateAlertStatus: (id: string, status: string): Promise<Alert> => 
    api.put(endpoints.alerts.updateStatus(id), { status }),
  deleteAlert: (id: string): Promise<void> => api.delete(endpoints.alerts.delete(id)),
  markMultipleAlertsAsRead: (alertIds: string[]): Promise<any> => 
    api.post(endpoints.alerts.markAllRead, { alert_ids: alertIds }),
  markAllSystemAlertsAsRead: (): Promise<{ updated_count: number; message?: string; status?: string }> => 
    api.post(endpoints.alerts.markAllSystemRead),
  getAlertDetails: (id: number | string): Promise<Alert> => api.get<Alert>(endpoints.alerts.detail(id)),
  resolveAlert: (id: number | string, comments?: string): Promise<Alert> => api.put<Alert>(endpoints.alerts.resolve(id), { comments }),
  commentOnAlert: (id: number | string, comment: string): Promise<Alert> => api.post<Alert>(endpoints.alerts.comment(id), { comment }),
  getAlertStats: (): Promise<{ unreadCount: number; totalCount: number; highPriorityCount: number; }> => api.get(endpoints.alerts.stats),
};

// Report functions
export const reportsApi = {
  getReports: (): Promise<Report[]> => api.get<Report[]>(endpoints.reports.list),
  getFsReports: (): Promise<FsReportInfo[]> => api.get<FsReportInfo[]>(endpoints.reports.fs),
  getReportDetails: (id: number | string): Promise<Report> => api.get<Report>(endpoints.reports.detail(id)),
  generateReport: (params: ReportGenerationParams): Promise<Report> => api.post<Report>(endpoints.reports.generate, params),
  getReportDownloadUrl: (id: number | string): string => `${api['baseUrl']}${endpoints.reports.download(id)}`,
  getHtmlReportUrl: (filename: string): string => `${api['baseUrl']}${endpoints.reports.html(filename)}`,
};

// Settings functions
export const settingsApi = {
  getGeneralSettings: (): Promise<GeneralSettings> => api.get<GeneralSettings>(endpoints.settings.general),
  updateGeneralSettings: (data: GeneralSettings): Promise<GeneralSettings> => api.put<GeneralSettings>(endpoints.settings.general, data),
  getDetectionSettings: (): Promise<DetectionSettings> => api.get<DetectionSettings>(endpoints.settings.detection),
  updateDetectionSettings: (data: DetectionSettings): Promise<DetectionSettings> => api.put<DetectionSettings>(endpoints.settings.detection, data),
  getNetworkSettings: (): Promise<NetworkSettings> => api.get<NetworkSettings>(endpoints.settings.network),
  updateNetworkSettings: (data: NetworkSettings): Promise<NetworkSettings> => api.put<NetworkSettings>(endpoints.settings.network, data),
  getNotificationSettings: (): Promise<NotificationSettings> => api.get<NotificationSettings>(endpoints.settings.notification),
  updateNotificationSettings: (data: NotificationSettings): Promise<NotificationSettings> => api.put<NotificationSettings>(endpoints.settings.notification, data),
};

// System functions
export const systemApi = {
  getSystemInfo: (): Promise<SystemInfo> => api.get<SystemInfo>(endpoints.settings.system.info),
  getSystemLogs: (params = {}): Promise<any> => api.get(endpoints.settings.system.logs, params), // Define specific log type if known
  restartSystem: (): Promise<any> => api.post(endpoints.settings.system.restart),
};

// Prevention functions
export const preventionApi = {
  getPreventionSettings: (): Promise<PreventionSettings> => api.get<PreventionSettings>(endpoints.prevention.settings),
  updatePreventionSettings: (data: PreventionSettings): Promise<PreventionSettings> => api.put<PreventionSettings>(endpoints.prevention.settings, data),
  getBlockedIps: (): Promise<BlockedIp[]> => api.get<BlockedIp[]>(endpoints.prevention.blockedIps),
  blockIp: (ip: string, reason?: string): Promise<BlockedIp> => api.post<BlockedIp>(endpoints.prevention.block, { ip, reason }),
  unblockIp: (ip: string): Promise<any> => api.delete(endpoints.prevention.unblock(ip)),
};

// Health check function
export const checkHealth = (): Promise<any> => api.get(endpoints.health); // Define specific health status type if known

// FAQ functions
export const faqApi = {
  getFaqItems: (): Promise<FAQItem[]> => api.get<FAQItem[]>(endpoints.faq),
};

export default api;