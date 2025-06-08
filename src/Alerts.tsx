import React, { useState, useEffect, useMemo } from 'react';
import "./styles/Alerts.css";
import { Alert, alertsApi } from './services/api';
import { sendTrayNotification } from './services/tray-events';

type AlertSeverity = 'High' | 'Medium' | 'Low' | '';
type SortField = 'timestamp' | 'severity' | 'source_ip' | 'destination_ip'; // Updated for consistency
type SortDirection = 'asc' | 'desc';

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]); // Holds alerts for the current page from API
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState(''); // New state for success messages
  const [filterSeverity, setFilterSeverity] = useState<AlertSeverity>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUnreadOnly, setFilterUnreadOnly] = useState(false); // New state for unread filter
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(20); // Match API limit for server-side pagination
  const [totalPages, setTotalPages] = useState(1); // Total pages from API response
  const [refreshKey, setRefreshKey] = useState(0); // New state to trigger data refresh

  useEffect(() => {
    // SSE connection for real-time updates
    // Ensure the URL matches your API base URL + /alerts/stream
    // This uses a relative path, assuming the frontend is served from the same origin as the API
    // or a proxy is configured.
    const eventSource = new EventSource('/api/v1/alerts/stream');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data && data.type === 'refresh_alerts') {
          console.log('SSE: Received refresh_alerts notification, triggering data refresh.');
          setRefreshKey(prev => prev + 1); // Trigger data re-fetch
          
          // Send notification for new alerts
          if (data.alert) {
            const alert = data.alert;
            if (alert.severity === 'High') {
              sendTrayNotification(
                `High Severity Alert`,
                `${alert.description}\nSource: ${alert.source_ip || 'Unknown'}`
              );
            }
          }
        }
      } catch (e) {
        console.error('SSE: Error parsing message data or unexpected data format:', event.data, e);
      }
    };

    eventSource.onerror = (err) => {
      console.error('EventSource failed:', err);
      // Optionally, you might want to implement reconnection logic here or close and retry.
      // For now, just logging the error.
      eventSource.close(); // Close on error to prevent constant retries if server is down
    };

    // Cleanup on component unmount
    return () => {
      console.log('Closing EventSource connection.');
      eventSource.close();
    };
  }, []); // Empty dependency array ensures this runs only on mount and unmount

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true);
        console.log(`Fetching alerts for page: ${currentPage}, limit: ${itemsPerPage}`);
        const params: any = { // Use 'any' for params object or define a more specific type
          page: currentPage,
          limit: itemsPerPage,
        };
        // Add severity filter to params if API supports it and filterSeverity is set
        if (filterSeverity) {
          params.severity = filterSeverity;
        }
        // Add status filter if filterUnreadOnly is true
        if (filterUnreadOnly) {
          params.status = 'new'; // Assuming 'new' status corresponds to 'unread' in backend
        }
        // Add search term to params if API supports it and searchTerm is set
        // Example: if (searchTerm) params.search = searchTerm;
        // Add sorting to params if API supports it
        // Example: params.sort_by = sortField; params.sort_direction = sortDirection;


        const response = await alertsApi.getAlerts(params);
        console.log("Raw API response for alerts:", response);

        if (response && Array.isArray(response.alerts)) {
          // console.log("First alert object from response (stringified):", JSON.stringify(response.alerts[0], null, 2));
          console.log("Fetched alerts (after refresh/mark all read if applicable):", response.alerts.map(a => ({ id: a.alert_id, status: a.status }))); // Log statuses
          setAlerts(response.alerts);
          setTotalPages(response.total_pages || 1);
        } else {
          console.error('Fetched alerts data is not in the expected format, is empty, or alerts array is missing:', response);
          setAlerts([]);
          setTotalPages(1);
          setError('Failed to load alerts: Invalid data format received.');
        }
        setLoading(false);
      } catch (err) {
        console.error('Failed to fetch alerts (in catch block):', err);
        setError('Failed to load alerts. Please try again later.');
        setAlerts([]);
        setTotalPages(1);
        setLoading(false);
      }
    };

    fetchAlerts();
  }, [currentPage, itemsPerPage, filterSeverity, searchTerm, sortField, sortDirection, filterUnreadOnly, refreshKey]); // Re-fetch when page, itemsPerPage or server-side filters change

  const handleToggleReadStatus = async (alertId: string, currentStatus: 'read' | 'unread' | string | undefined) => {
    if (!alertId) {
      console.error("Toggle read status failed: Alert ID is undefined.");
      setError("Could not update alert: ID missing.");
      return;
    }
    const newStatus = currentStatus === 'read' ? 'unread' : 'read';
    try {
      setLoading(true);
      await alertsApi.updateAlertStatus(alertId, newStatus);
      setAlerts(prevAlerts => prevAlerts.map(alert =>
        alert.alert_id === alertId ? { ...alert, status: newStatus } : alert
      ));
      setError('');
      // TODO: Here you would typically trigger a refresh of global alert stats for the navbar
      // For example, by calling a function that refetches stats or dispatching a global state update.
      // e.g., refreshNavbarAlertCount(); or dispatch({ type: 'ALERT_STATUS_CHANGED' });
    } catch (err) {
      console.error('Failed to update alert status:', err);
      console.error('Error details:', err instanceof Error ? err.message : String(err));
      setError('Failed to update alert status. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const filteredAndSortedAlerts = useMemo(() => {
    // Client-side filtering and sorting is applied to the current page's data
    // If filtering/sorting were fully server-side, this logic might be simpler or removed.
    let processedAlerts = [...alerts];

    // Log the first few alerts and their IDs to understand their structure
    // if (alerts && alerts.length > 0) {
    //   console.log("Raw alerts data for current page (first 5 stringified):");
    //   alerts.slice(0, 5).forEach((alert, index) => {
    //     console.log(`Alert ${index + 1}:`, JSON.stringify(alert, null, 2));
    //   });
    // }

    // Apply severity filter (client-side for current page data)
    // If API handles severity filter, this specific client-side filter might be redundant
    // or only needed if API doesn't support filtering by it.
    // if (filterSeverity) {
    //   processedAlerts = processedAlerts.filter(alert => alert.severity.toLowerCase() === filterSeverity.toLowerCase());
    // }

    // Apply search term filter (client-side for current page data)
    if (searchTerm) {
      const lowerSearchTerm = searchTerm.toLowerCase();
      processedAlerts = processedAlerts.filter(alert =>
        alert.description.toLowerCase().includes(lowerSearchTerm) ||
        (alert.source_ip && alert.source_ip.toLowerCase().includes(lowerSearchTerm)) ||
        (alert.destination_ip && alert.destination_ip.toLowerCase() === lowerSearchTerm)
      );
    }

    // Apply sorting (client-side for current page data)
    // If API handles sorting, this client-side sort might be redundant.
    processedAlerts.sort((a, b) => {
      const getComparableValue = (obj: Alert, field: SortField) => {
        const value = obj[field as keyof Alert];
        // Treat undefined or null values as empty strings for robust comparison
        return value === undefined || value === null ? '' : String(value);
      };

      const valA = getComparableValue(a, sortField);
      const valB = getComparableValue(b, sortField);

      let comparison = 0;
      if (valA.localeCompare(valB) > 0) {
        comparison = 1;
      } else if (valA.localeCompare(valB) < 0) {
        comparison = -1;
      }

      return sortDirection === 'asc' ? comparison : comparison * -1;
    });

    return processedAlerts;

  }, [alerts, filterSeverity, searchTerm, sortField, sortDirection]); // Dependencies for client-side processing

  // useEffect(() => {
  //   // This useEffect was for client-side pagination logic.
  //   // With server-side pagination, if currentPage > totalPages (from API),
  //   // it typically means the data changed such that the current page no longer exists.
  //   // A robust way to handle this might be to navigate to the new actual last page,
  //   // or page 1 if totalPages becomes 0. For now, this is commented out.
  //   // if (currentPage > totalPages && totalPages > 0) {
  //   //   setCurrentPage(1);
  //   // }
  // }, [currentPage, totalPages]);

  const handleMarkAllRead = async () => {
    setLoading(true);
    setError("");
    setSuccessMessage(""); // Clear previous success messages
    try {
      // Call the new system-wide mark all read API
      const response = await alertsApi.markAllSystemAlertsAsRead();
      console.log("Mark all system alerts as read response:", response);

      setSuccessMessage(`Successfully marked ${response.updated_count} alerts as read system-wide.`);
      
      // Trigger a re-fetch of alerts
      setRefreshKey(prev => prev + 1);

      // If "Unread Only" filter is active, it's likely the current view will be empty or much smaller.
      // Resetting to page 1 provides a better user experience.
      if (filterUnreadOnly) {
        setCurrentPage(1);
      }

      // The optimistic update below is removed as the re-fetch (triggered by refreshKey)
      // will ensure the UI reflects the true state from the backend.
      // setAlerts(prevAlerts =>
      //   prevAlerts.map(alert => ({ ...alert, status: 'read' }))
      // );

    } catch (err) {
      console.error('Failed to mark all system alerts as read:', err);
      setError('Failed to mark all system alerts as read. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp: any): string => {
    if (typeof timestamp === 'string') {
      try {
        return new Date(timestamp).toLocaleString();
      } catch (e) {
        return 'Invalid Date String';
      }
    }
    if (timestamp && typeof timestamp === 'object' && timestamp.$date && typeof timestamp.$date === 'object' && timestamp.$date.$numberLong) {
      try {
        const dateNumber = parseInt(timestamp.$date.$numberLong, 10);
        if (isNaN(dateNumber)) return 'Invalid Date Number';
        return new Date(dateNumber).toLocaleString();
      } catch (e) {
        return 'Error Parsing Date';
      }
    }
    if (timestamp && typeof timestamp === 'object' && timestamp.$date && typeof timestamp.$date === 'string') {
      try {
        return new Date(timestamp.$date).toLocaleString();
      } catch (e) {
        return 'Error Parsing Old Date Format';
      }
    }
    return 'Invalid Date Object';
  };

  const handleSort = (field: SortField) => {
    const newDirection = sortField === field && sortDirection === 'desc' ? 'asc' : 'desc';
    setSortField(field);
    setSortDirection(newDirection);
    // setCurrentPage(1); // Reset to first page on sort if sorting is server-side.
                       // If client-side sort on current page data, this might not be desired.
                       // For now, client-side sorting doesn't reset page.
  };
  
  const handleSeverityFilterChange = (newSeverity: AlertSeverity) => {
    setFilterSeverity(newSeverity);
    setCurrentPage(1); // Reset to page 1 when global filters change
  };

  const handleSearchTermChange = (newSearchTerm: string) => {
    setSearchTerm(newSearchTerm);
    setCurrentPage(1); // Reset to page 1 when global filters change
  };

  const handleFilterUnreadOnlyChange = (isChecked: boolean) => {
    setFilterUnreadOnly(isChecked);
    setCurrentPage(1); // Reset to page 1 when this filter changes
  };


  const goToNextPage = () => {
    if (currentPage < totalPages) {
      setCurrentPage(prev => prev + 1);
    }
  };

  const goToPrevPage = () => setCurrentPage(prev => Math.max(1, prev - 1));

  return (
    <>
      <main className="container alerts-page">
        <h1>Security Alerts</h1>

        {error && <div className="error-message">{error}</div>}
        {successMessage && <div className="success-message">{successMessage}</div>} {/* Display success message */}

        <section className="alert-controls">
          <div className="filter-group">
            <label htmlFor="severity-filter">Filter by Severity:</label>
            <select
              id="severity-filter"
              value={filterSeverity}
              onChange={(e) => handleSeverityFilterChange(e.target.value as AlertSeverity)}
            >
              <option value="">All Severities</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
          <div className="filter-group">
            <label htmlFor="search-term">Search:</label>
            <input
              type="text"
              id="search-term"
              placeholder="Search IP or description..."
              value={searchTerm}
              onChange={(e) => handleSearchTermChange(e.target.value)}
            />
          </div>
          <div className="filter-group">
            <input
              type="checkbox"
              id="unread-only-filter"
              checked={filterUnreadOnly}
              onChange={(e) => handleFilterUnreadOnlyChange(e.target.checked)}
            />
            <label htmlFor="unread-only-filter" style={{ marginLeft: '5px' }}>Unread Only</label>
          </div>
          <div className="filter-group">
            <button onClick={handleMarkAllRead} className="mark-all-read-button">
              Mark All Read
            </button>
          </div>
        </section>

        <section className="alerts-table-section">
          {loading ? (
            <div className="loading-spinner">Loading alerts...</div>
          ) : (
            <div className="table-responsive">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th onClick={() => handleSort('timestamp')}>Timestamp {sortField === 'timestamp' ? (sortDirection === 'desc' ? '▼' : '▲') : ''}</th>
                    <th onClick={() => handleSort('severity')}>Severity {sortField === 'severity' ? (sortDirection === 'desc' ? '▼' : '▲') : ''}</th>
                    <th onClick={() => handleSort('source_ip')}>Source IP {sortField === 'source_ip' ? (sortDirection === 'desc' ? '▼' : '▲') : ''}</th>
                    <th onClick={() => handleSort('destination_ip')}>Destination IP {sortField === 'destination_ip' ? (sortDirection === 'desc' ? '▼' : '▲') : ''}</th>
                    <th>Protocol</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAndSortedAlerts.map(alert => {
                    // Ensure alertId for API calls is alert.alert_id
                    const apiAlertId = alert.alert_id;
                    // For React key, use a robust fallback
                    const reactKey = alert.alert_id || alert.id?.toString() || alert._id?.toString();
                    return (
                      <tr key={reactKey} className={`severity-row-${alert.severity.toLowerCase()} ${alert.status === 'read' ? 'status-read' : ''}`}>
                        <td>{formatTimestamp(alert.timestamp)}</td>
                        <td><span className={`severity-indicator severity-${alert.severity.toLowerCase()}`}>{alert.severity}</span></td>
                        <td>{alert.source_ip}</td>
                        <td>{alert.destination_ip}</td>
                        <td>{alert.protocol}</td>
                        <td>{alert.description}</td>
                        <td>{alert.status === 'read' ? 'Read' : 'Unread'}</td>
                        <td>
                          <button 
                            onClick={() => apiAlertId && handleToggleReadStatus(apiAlertId, alert.status)} 
                            disabled={!apiAlertId || loading}
                            className="toggle-read-status-button"
                          >
                            {alert.status === 'read' ? 'Mark Unread' : 'Mark Read'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredAndSortedAlerts.length === 0 && !loading && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '20px' }}>
                        No alerts match the current filters for this page.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="pagination-controls">
          <span>Page {currentPage} of {totalPages}</span>
          <button onClick={goToPrevPage} disabled={currentPage === 1}>Previous</button>
          <button onClick={goToNextPage} disabled={currentPage >= totalPages}>Next</button>
        </section>

      </main>
    </>
  );
};

export default Alerts;
