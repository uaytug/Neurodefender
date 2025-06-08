import React, { useState, useEffect } from 'react';
import "./styles/Dashboard.css";
import {
  Alert,
  TrafficData,
  TrafficHistoryDataPoint,
} from "./services/api";
import {
  dashboardApi,
} from "./services/tauri-api";

// Helper function to format timestamp (assuming similar structure as in Alerts.tsx)
// This should ideally be in a shared utility file
const formatTimestamp = (timestamp: any): string => {
  if (typeof timestamp === 'string') {
    // If it's already a string (e.g., from RFC3339)
    try {
      return new Date(timestamp).toLocaleString();
    } catch (e) {
      return 'Invalid Date String';
    }
  }
  if (timestamp && typeof timestamp === 'object' && timestamp.$date && typeof timestamp.$date === 'object' && timestamp.$date.$numberLong) {
    // MongoDB BSON date format
    try {
      const dateNumber = parseInt(timestamp.$date.$numberLong, 10);
      if (isNaN(dateNumber)) return 'Invalid Date Number';
      return new Date(dateNumber).toLocaleString();
    } catch (e) {
      return 'Error Parsing Date';
    }
  }
  if (timestamp && typeof timestamp === 'object' && timestamp.$date && typeof timestamp.$date === 'string') {
    // Older MongoDB BSON date string format (less common)
    try {
      return new Date(timestamp.$date).toLocaleString();
    } catch (e) {
      return 'Error Parsing Old Date Format';
    }
  }
  return 'Invalid Date Object'; // Fallback for unknown formats
};

const Dashboard: React.FC = () => {
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [trafficData, setTrafficData] = useState<TrafficData>({
    inbound: 0,
    outbound: 0,
    blockedConnections: 0,
    threatsBlockedToday: 0,
  });
  // const [systemHealth, setSystemHealth] = useState({
  //   cpu: 0,
  //   memory: 0,
  //   disk: 0,
  //   uptime: ''
  // });
  const [trafficHistory, setTrafficHistory] = useState<TrafficHistoryDataPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchAllDashboardData = async () => {
      try {
        setLoading(true);
        setError('');

        // Fetch all dashboard data first as it might contain everything needed
        const allData = await dashboardApi.getDashboardData();
        if (allData) {
          setRecentAlerts(allData.recent_alerts || []);
          if (allData.traffic_stats) {
            setTrafficData({
              inbound: allData.traffic_stats.inbound_mbps || 0,
              outbound: allData.traffic_stats.outbound_mbps || 0,
              blockedConnections: allData.traffic_stats.blocked_connections || 0,
              threatsBlockedToday: allData.traffic_stats.threats_blocked_today || 0,
            });
          }
          if (allData.system_health) {
            // const uptimeInSeconds = allData.system_health.uptime_seconds || 0;
            // const days = Math.floor(uptimeInSeconds / (3600 * 24));
            // const hours = Math.floor((uptimeInSeconds % (3600 * 24)) / 3600);
            // const minutes = Math.floor((uptimeInSeconds % 3600) / 60);
            // const formattedUptime = `${days}d ${hours}h ${minutes}m`;

            // setSystemHealth({
            //   cpu: allData.system_health.cpu_usage || 0,
            //   memory: allData.system_health.memory_usage || 0,
            //   disk: allData.system_health.disk_usage || 0,
            //   uptime: formattedUptime,
            // });
          }
        } else {
          // Fallback to individual fetches if allData is not comprehensive or fails partially
          const alerts = await dashboardApi.getRecentAlerts();
          setRecentAlerts(alerts);

          const traffic = await dashboardApi.getTrafficData();
          setTrafficData(traffic); // This correctly maps nested fields now

          // const systemInfo = await systemApi.getSystemInfo();
          // systemInfo.uptime is already a string, so no need for uptime_seconds or formatting here
          // setSystemHealth({
          //     cpu: systemInfo.cpu_usage,
          //     memory: systemInfo.memory_usage,
          //     disk: systemInfo.disk_usage, // Assuming disk_usage is a percentage
          //     uptime: systemInfo.uptime, // Use the pre-formatted string directly
          // });
        }

        const history = await dashboardApi.getTrafficHistory();
        setTrafficHistory(history);

        setLoading(false);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
        setError('Failed to load dashboard data. Please try again later.');
        setLoading(false);
      }
    };

    fetchAllDashboardData();
  }, []);

  return (
    <>
      <h1>Dashboard Overview</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      <div className="status-indicator">
        <span className="status-label">Security Status:</span>
        <span className="status-protected">Protected</span>
        <div className="network-activity dashboard-activity">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="activity-dot"></div>
          ))}
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="dashboard-grid">
        {/* Recent Alerts Section */}
        <section className="dashboard-widget interactive-card recent-alerts">
          <div className="widget-header">
            <h2>Recent Alerts</h2>
            <div className="widget-controls">
              <div className="control-button tooltip">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="1"></circle>
                  <circle cx="19" cy="12" r="1"></circle>
                  <circle cx="5" cy="12" r="1"></circle>
                </svg>
                <span className="tooltip-text">More Options</span>
              </div>
            </div>
          </div>
          {loading ? (
            <div className="loading-spinner">Loading alerts...</div>
          ) : (
            <ul className="alert-list">
              {recentAlerts.map(alert => (
                <li key={alert.alert_id || alert.id} className={`severity-${alert.severity.toLowerCase()}`}>
                  <span className="alert-timestamp">{formatTimestamp(alert.timestamp)}</span>
                  <span className="alert-severity">[{alert.severity}]</span>
                  <span className="alert-description">{alert.description}</span>
                </li>
              ))}
            </ul>
          )}
          <a href="/alerts" className="widget-link">View All Alerts <span className="widget-link-arrow">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12"></line>
              <polyline points="12 5 19 12 12 19"></polyline>
            </svg>
          </span></a>
        </section>

        {/* Network Traffic Overview */}
        <section className="dashboard-widget interactive-card traffic-overview">
          <div className="widget-header">
            <h2>Network Traffic</h2>
            <div className="widget-controls">
              <div className="control-button tooltip">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 20v-6M6 20V10M18 20V4"></path>
                </svg>
                <span className="tooltip-text">View Analytics</span>
              </div>
            </div>
          </div>
          {loading ? (
            <div className="loading-spinner">Loading traffic data...</div>
          ) : (
            <div className="traffic-metrics">
              <div className="traffic-item">
                <div className="traffic-label">
                  <div className="traffic-indicator inbound"></div>
                  <span>Inbound:</span>
                </div>
                <span className="traffic-value">{trafficData.inbound} Mbps</span>
              </div>
              <div className="traffic-item">
                <div className="traffic-label">
                  <div className="traffic-indicator outbound"></div>
                  <span>Outbound:</span>
                </div>
                <span className="traffic-value">{trafficData.outbound} Mbps</span>
              </div>
              <div className="traffic-item">
                <div className="traffic-label">
                  <div className="traffic-indicator blocked"></div>
                  <span>Blocked Today:</span>
                </div>
                <span className="traffic-value">{trafficData.blockedConnections}</span>
              </div>
            </div>
          )}
          {/* Traffic chart visualization */}
          <div className="traffic-chart">
            <div className="chart-lines">
              <div className="chart-line"></div>
              <div className="chart-line"></div>
              <div className="chart-line"></div>
            </div>
            <div className="chart-bars">
              {trafficHistory.length > 0 ? trafficHistory.map((dataPoint, i) => (
                <div key={dataPoint.timestamp || i} className="chart-bar-container">
                  <div 
                    className="chart-bar" 
                    style={{ 
                      height: `${Math.min(100, (dataPoint.value / Math.max(...trafficHistory.map(p => p.value))) * 100 || 10)}%`,
                      opacity: 1
                    }}
                    title={`Value: ${dataPoint.value}`}
                  ></div>
                </div>
              )) : Array.from({ length: 12 }).map((_, i) => (
                <div key={i} className="chart-bar-container">
                    <div className="chart-bar" style={{ height: '10%', opacity: 0.5 }}></div>
                </div>
              ))}
            </div>
            <div className="chart-overlay"></div>
          </div>
        </section>

        <section className="dashboard-widget interactive-card threats-blocked-widget">
          <div className="widget-header">
            <h2>Threats Blocked Today</h2>
            <div className="widget-controls">
              <div className="control-button tooltip">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <span className="tooltip-text">Security Status</span>
              </div>
            </div>
          </div>
          {loading ? (
            <div className="loading-spinner">Loading threats data...</div>
          ) : (
            <div className="widget-content">
              <div className="threats-summary">
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
                </div>
                <div className="stat-label">Blocked Threats</div>
              </div>
              
              <div className="threats-list">
                {recentAlerts
                  .filter(alert => {
                    // Same filtering logic as above
                    if (alert.severity?.toLowerCase() !== 'high') return false;
                    
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
                  })
                  .slice(0, 3) // Show only the first 3 threats
                  .map(alert => (
                    <div key={alert.alert_id || alert.id} className="threat-item">
                      <div className="threat-indicator high"></div>
                      <div className="threat-details">
                        <div className="threat-time">{formatTimestamp(alert.timestamp).split(',')[1]?.trim() || 'Unknown time'}</div>
                        <div className="threat-description">{alert.description}</div>
                      </div>
                    </div>
                  ))
                }
                {recentAlerts.filter(alert => {
                  if (alert.severity?.toLowerCase() !== 'high') return false;
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
                }).length === 0 && (
                  <div className="no-threats">
                    <div className="no-threats-icon">
                      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                      </svg>
                    </div>
                    <div className="no-threats-text">No blocked threats today</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </section>

        {/* Threat Map */}
        <section className="dashboard-widget interactive-card threat-map">
          <div className="widget-header">
            <h2>Global Threat Activity</h2>
            <div className="widget-controls">
              <div className="control-button tooltip">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="8" x2="12" y2="12"></line>
                  <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <span className="tooltip-text">Information</span>
              </div>
            </div>
          </div>
          <div className="map-container">
            {loading ? (
              <div className="loading-spinner">Loading threat data...</div>
            ) : (
              <>
                <iframe 
                  width="100%" 
                  height="300" 
                  src="https://cybermap.kaspersky.com/en/widget/dynamic/dark" 
                  frameBorder="0"
                  title="Kaspersky Cyberthreat Map"
                ></iframe>
              </>
            )}
          </div>
        </section>

        {/* Placeholder for "Threats Blocked Today" Card - User should integrate this where appropriate */}

      </div>
    </>
  );
};

export default Dashboard;

