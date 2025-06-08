import React from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import Navbar from './Navbar';
import Dashboard from './Dashboard';
import Alerts from './Alerts';
import Reports from './Reports';
import Settings from './Settings';
import FAQ from './FAQ';
import AboutUs from './AboutUs';
import "./styles/App.css";
import { useEffect, useState } from 'react';
import { dashboardApi, Alert as ApiAlert } from './services/api'; // Import dashboardApi, DashboardData, and Alert as ApiAlert
import showSystemInfo from './services/sysinfo';
import { useTrayEventListeners, updateTrayState } from './services/tray-events';


// Quick Action Card Component
const QuickActionCard: React.FC<{
  title: string;
  description: string;
  icon: React.ReactNode;
  path: string;
  count?: number;
}> = ({ title, description, icon, path, count }) => {
  const navigate = useNavigate();
  
  return (
    <div className="quick-action-card interactive-card" onClick={() => navigate(path)}>
      <div className="quick-action-header">
        <div className="quick-action-icon">{icon}</div>
        <h3>{title}</h3>
        {count !== undefined && <span className="quick-action-count futuristic-badge">{count}</span>}
      </div>
      <p>{description}</p>
      <div className="quick-action-bottom">
        <button className="quick-action-button">Open {title}</button>
      </div>
    </div>
  );
};



// Component for the Home Page content
const HomePage: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<string>("Running");
  const [cpuUsage, setCpuUsage] = useState<number>(0);
  const [memoryUsage, setMemoryUsage] = useState<number>(0);
  const [uptime, setUptime] = useState<string>("");
  const [activeAlerts, setActiveAlerts] = useState<number>(0);
  const [monitoredDevices, setMonitoredDevices] = useState<string>("");
  const [recentAlerts, setRecentAlerts] = useState<ApiAlert[]>([]); // Use ApiAlert type

  useEffect(() => {
  const fetchHomePageData = async () => {
    try {
      // Fetch main dashboard data which includes system_status, cpu_usage, memory_usage, uptime, etc.
      const mainDashboardData = await dashboardApi.getDashboardData();
      console.log("Full mainDashboardData received:", mainDashboardData); // Log the full response for debugging
      const systemInfo = await showSystemInfo(); // For deviceName and potentially more accurate local CPU/RAM if preferred
      
      if (typeof mainDashboardData.system_status === 'string') { // Rust returns system_status
        setSystemStatus(mainDashboardData.system_status);
      } else {
        console.warn('mainDashboardData.system_status is not a string or is undefined. Defaulting systemStatus.', mainDashboardData);
        setSystemStatus("Unknown"); 
      }

      // Use values from mainDashboardData (which comes from Rust get_dashboard_data handler)
      // This handler already gets cpu_usage, memory_usage, uptime from monitor_service
      setCpuUsage(mainDashboardData.system_health.cpu_usage || 0); 
      setMemoryUsage(mainDashboardData.system_health.memory_usage || 0);
      setUptime(formatUptime(mainDashboardData.system_health.uptime_seconds) || "N/A");
      
      setActiveAlerts(mainDashboardData.alerts_by_status?.new || 0); // Assuming 'new' count for active
      // Try to get today's high priority alerts from alerts_by_severity
      setMonitoredDevices(systemInfo.deviceName || "Unknown"); 
      
      // Set threatsBlockedToday using its original source if still needed elsewhere, or remove if replaced entirely
      // For now, let's assume the card is fully replaced by "Today's High Priority Alerts"
      // setThreatsBlockedToday(mainDashboardData.traffic_stats.blocked_connections || 0);

      setRecentAlerts(mainDashboardData.recent_alerts.slice(0, 3));

      // Update tray state with current system info
      const isMonitoring = mainDashboardData.system_status === "Running";
      await updateTrayState({
        isMonitoring,
        alertCount: mainDashboardData.alerts_by_status?.new || 0,
        cpuUsage: mainDashboardData.system_health.cpu_usage || 0,
        memoryUsage: mainDashboardData.system_health.memory_usage || 0,
      });

    } catch (err) {
      console.error("Failed to fetch dashboard stats or recent alerts:", err);
      setSystemStatus("Unavailable");
      setCpuUsage(0);
      setMemoryUsage(0);
      setUptime("Error");
      setActiveAlerts(0);
      setMonitoredDevices("Unknown");
      // setThreatsBlockedToday(0); // Reset if it were still used
      setRecentAlerts([]);
    }
  };
  
  fetchHomePageData();
  
  // Set up periodic updates every 30 seconds
  const interval = setInterval(fetchHomePageData, 30000);
  
  return () => clearInterval(interval);
}, []);

// Helper function to format uptime from seconds to a readable string
const formatUptime = (totalSeconds: number): string => {
  if (isNaN(totalSeconds) || totalSeconds < 0) return "N/A";

  const days = Math.floor(totalSeconds / (3600 * 24));
  const hours = Math.floor((totalSeconds % (3600 * 24)) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);

  let uptimeString = '';
  if (days > 0) uptimeString += `${days}d `;
  if (hours > 0) uptimeString += `${hours}h `;
  if (minutes > 0 || (days === 0 && hours === 0)) uptimeString += `${minutes}m`;
  
  return uptimeString.trim() || "0m";
};


  return (
    <>
      <div className="app-header">
        <div className="app-header-content">
          <div className="welcome-greeting">
            <h1>Security Overview</h1>
            <div className="last-session">
              <span>Uptime: {uptime}</span>
              <div className="system-pulse-container">
                <div className="system-pulse"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Status Overview */}
      <div className="app-status-overview">
        <div className="status-card interactive-card">
          <div className="status-card-header">
            <h3>Security Status</h3>
            <span className={`status-${systemStatus.toLowerCase()}`}>{systemStatus}</span>
          </div>
          <div className="status-card-body">
            <div className="status-metric">
              <span className="status-metric-label">CPU</span>
              <span className="status-metric-value">{cpuUsage.toFixed(2)}%</span>
              <div className="progress-container">
                <div className="progress-bar" style={{width: `${cpuUsage}%`}}></div>
              </div>
            </div>
            <div className="status-metric">
              <span className="status-metric-label">Memory</span>
              <span className="status-metric-value">{memoryUsage.toFixed(2)}%</span>
              <div className="progress-container">
                <div className="progress-bar" style={{width: `${memoryUsage}%`}}></div>
              </div>
            </div>
          </div>
          <div className="network-activity dashboard-activity">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="activity-dot"></div>
            ))}
          </div>
        </div>

        <div className="status-metrics-row">
          <div className="status-metric-item interactive-card">
            <h4>Active Alerts</h4>
            <p className="metric-value">{activeAlerts}</p>
          </div>
          <div className="status-metric-item interactive-card">
            <h4>This Device</h4>
            <p className="metric-value">{monitoredDevices}</p>
          </div>
          <div className="status-metric-item interactive-card">
            <h4>Blocked Threats</h4>
            <div className="stat-value">
                {recentAlerts.filter(alert => {
                      // Filter for high-severity alerts from today
                      if (alert.severity?.toLowerCase() !== 'high') return false;
                      
                      // Check if alert is from today
                      let alertDate;
                      try {
                        if (typeof alert.timestamp === 'string') {
                          alertDate = new Date(alert.timestamp);
                        } else if (alert.timestamp && typeof alert.timestamp === 'object' && alert.timestamp.$date && typeof alert.timestamp.$date === 'object' && alert.timestamp.$date.$numberLong) {
                          alertDate = new Date(parseInt(alert.timestamp.$date.$numberLong, 10));
                        } else if (alert.timestamp && typeof alert.timestamp === 'object' && alert.timestamp.$date && typeof alert.timestamp.$date === 'string') {
                          alertDate = new Date(alert.timestamp.$date);
                        } else {
                          return false;
                        }
                        
                        const today = new Date();
                        return alertDate.toDateString() === today.toDateString();
                      } catch (e) {
                        return false;
                      }
                    }).length}
                  <div className="stat-label">Blocked Threats</div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="section-header">
        <h2>Quick Actions</h2>
      </div>
      <div className="quick-actions-grid">
        <QuickActionCard 
          title="Dashboard" 
          description="View network monitoring dashboard with real-time analytics" 
          icon={
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="9"></rect>
              <rect x="14" y="3" width="7" height="5"></rect>
              <rect x="14" y="12" width="7" height="9"></rect>
              <rect x="3" y="16" width="7" height="5"></rect>
            </svg>
          }
          path="/dashboard" 
        />
        <QuickActionCard 
          title="Alerts" 
          description="Review and respond to security alerts and threats" 
          icon={
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
            </svg>
          }
          path="/alerts" 
          count={activeAlerts}
        />
        <QuickActionCard 
          title="Reports" 
          description="Generate and view security reports and analytics" 
          icon={
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
          }
          path="/reports" 
        />
        <QuickActionCard 
          title="Settings" 
          description="Configure system settings and detection parameters" 
          icon={
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
          } 
          path="/settings" 
        />
      </div>

      {/* Recent Alerts */}
      <div className="section-header with-action">
        <h2>Recent Alerts</h2>
        <a href="/alerts" className="section-action-link">View All</a>
      </div>
      <div className="recent-alerts-container">
        <ul className="home-alert-list">
          {recentAlerts.length > 0 ? recentAlerts.map(alert => (
            <li key={alert.id} className={`severity-${alert.severity.toLowerCase()}`}>
              <span className="alert-timestamp">{new Date(alert.timestamp as string).toLocaleString()}</span>
              <span className="alert-severity">[{alert.severity}]</span>
              <span className="alert-description">{alert.description}</span>
            </li>
          )) : (
            <li>No recent alerts.</li>
          )}
        </ul>
      </div>
    </>
  );
}

const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <>
      <Navbar />
      <main className="app-main">
        <div className="container">
          {children}
        </div>
      </main>
    </>
  );
};

function App() {
  // Initialize tray event listeners
  useTrayEventListeners();

  useEffect(() => {
    // Global error handler for unhandled promise rejections
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
      event.preventDefault(); // Prevent the default browser behavior
      
      // You could show a user-friendly notification here
      // For now, just log it to prevent crashes
    };

    // Global error handler for uncaught errors
    const handleError = (event: ErrorEvent) => {
      console.error('Uncaught error:', event.error);
      event.preventDefault(); // Prevent the default browser behavior
    };

    // Add event listeners
    window.addEventListener('unhandledrejection', handleUnhandledRejection);
    window.addEventListener('error', handleError);

    // Cleanup function
    return () => {
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
      window.removeEventListener('error', handleError);
    };
  }, []);

  return (
    <>
      <Routes>
        <Route path="/" element={
          <AppLayout>
            <HomePage />
          </AppLayout>
        } />
        <Route path="/dashboard" element={
          <AppLayout>
            <Dashboard />
          </AppLayout>
        } />
        <Route path="/alerts" element={
          <AppLayout>
            <Alerts />
          </AppLayout>
        } />
        <Route path="/reports" element={
          <AppLayout>
            <Reports />
          </AppLayout>
        } />
        <Route path="/settings" element={
          <AppLayout>
            <Settings />
          </AppLayout>
        } />
        <Route path="/faq" element={
          <AppLayout>
            <FAQ />
          </AppLayout>
        } />
        <Route path="/about" element={
          <AppLayout>
            <AboutUs />
          </AppLayout>
        } />
      </Routes>
    </>
  );
}

export default App;
