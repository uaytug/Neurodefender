import React, { useState, useEffect, useRef, useCallback } from 'react';
import "./styles/Reports.css";
import { Report, ReportGenerationParams, reportsApi, FsReportInfo } from './services/api'; // Updated imports
import { open } from '@tauri-apps/plugin-shell'; // Import open from tauri-apps plugin-shell

type ReportTypeOption = 'weekly' | 'monthly' | 'incident' | 'custom';

// Modal Component for HTML Reports
const HtmlReportModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  reportUrl: string;
  reportTitle: string;
}> = ({ isOpen, onClose, reportUrl, reportTitle }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content html-report-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>📊 {reportTitle}</h3>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <iframe
            src={reportUrl}
            width="100%"
            height="600px"
            frameBorder="0"
            title={reportTitle}
            className="report-iframe"
          />
        </div>
        <div className="modal-footer">
          <button onClick={() => window.open(reportUrl, '_blank')} className="btn-secondary">
            📤 Open in New Tab
          </button>
          <button onClick={onClose} className="btn-primary">
            ✓ Close
          </button>
        </div>
      </div>
    </div>
  );
};

// Error Boundary Component
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Reports component crashed:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <h2>Something went wrong with the Reports component</h2>
          <p>Error: {this.state.error?.message}</p>
          <button onClick={() => this.setState({ hasError: false, error: null })}>
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [fsReports, setFsReports] = useState<FsReportInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reportType, setReportType] = useState<ReportTypeOption>('weekly');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [backendAvailable, setBackendAvailable] = useState(true);
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    reportUrl: string;
    reportTitle: string;
  }>({
    isOpen: false,
    reportUrl: '',
    reportTitle: '',
  });
  
  // Ref to track if component is mounted
  const isMountedRef = useRef(true);
  
  // AbortController for cancelling requests
  const abortControllerRef = useRef<AbortController | null>(null);

  // Safe state setter that only updates if component is still mounted
  const safeSetState = useCallback((setter: React.Dispatch<React.SetStateAction<any>>, value: any) => {
    if (isMountedRef.current) {
      try {
        setter(value);
      } catch (error) {
        console.error('State update error:', error);
      }
    }
  }, []);

  // Show notification function
  const showNotification = useCallback((message: string, type: 'success' | 'error' | 'info' = 'info') => {
    safeSetState(setNotification, { message, type });
    setTimeout(() => {
      safeSetState(setNotification, null);
    }, 5000);
  }, [safeSetState]);

  const fetchReports = useCallback(async () => {
    // Cancel any ongoing request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    abortControllerRef.current = new AbortController();
    
    try {
      safeSetState(setLoading, true);
      safeSetState(setError, '');
      
      // Fetch both database and filesystem reports in parallel
      const [dbData, fsData] = await Promise.all([
        reportsApi.getReports().catch(() => []), // Fallback to empty array on error
        reportsApi.getFsReports().catch(() => []) // Fallback to empty array on error
      ]);
      
      // Validate response
      if (!isMountedRef.current) return;
      
      const validDbReports = Array.isArray(dbData) ? dbData.filter(report => 
        report && 
        typeof report === 'object' && 
        typeof report.report_id === 'string' && 
        typeof report.report_type === 'string'
      ) : [];

      const validFsReports = Array.isArray(fsData) ? fsData.filter(report => 
        report && 
        typeof report === 'object' && 
        typeof report.file_name === 'string'
      ) : [];
      
      safeSetState(setReports, validDbReports);
      safeSetState(setFsReports, validFsReports);
      safeSetState(setBackendAvailable, true);
    } catch (err) {
      if (!isMountedRef.current) return;
      
      console.error('Failed to fetch reports:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      
      if (errorMessage.includes('No response received from server') || 
          errorMessage.includes('Network Error') ||
          errorMessage.includes('timeout')) {
        safeSetState(setBackendAvailable, false);
        safeSetState(setError, 'Backend server is not available. Please ensure the server is running.');
      } else {
        safeSetState(setError, `Failed to load reports: ${errorMessage}`);
      }
      safeSetState(setReports, []); // Set empty array as fallback
      safeSetState(setFsReports, []); // Set empty array as fallback
    } finally {
      if (isMountedRef.current) {
        safeSetState(setLoading, false);
      }
    }
  }, [safeSetState]);

  useEffect(() => {
    isMountedRef.current = true;
    
    // Initial fetch with error handling
    fetchReports().catch(error => {
      console.error('Initial fetch failed:', error);
    });

    // Cleanup function to prevent state updates after unmount
    return () => {
      isMountedRef.current = false;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      setLoading(false);
      setIsGenerating(false);
    };
  }, [fetchReports]);

  const handleGenerateReport = useCallback(async () => {
    if (!isMountedRef.current) return;
    
    // Validation
    if (reportType === 'custom' && (!startDate || !endDate)) {
      showNotification('Please select a start and end date for custom range reports.', 'error');
      return;
    }

    if (!backendAvailable) {
      showNotification('Cannot generate report: Backend server is not available.', 'error');
      return;
    }

    // Cancel any ongoing request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    abortControllerRef.current = new AbortController();

    try {
      safeSetState(setIsGenerating, true);
      safeSetState(setError, '');

      const reportParams: ReportGenerationParams = {
        report_type: reportType,
        format: 'html',
        title: `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`,
        ...(reportType === 'custom' && { 
          period_start: startDate,
          period_end: endDate
        })
      };
      
      const newReport = await reportsApi.generateReport(reportParams);
      
      if (!isMountedRef.current) return;
      
      if (newReport && typeof newReport === 'object' && newReport.report_id) {
        showNotification(
          `Report '${newReport.report_id}' (${newReport.report_type}) generation initiated. Status: ${newReport.status}. Format: ${newReport.format}`,
          'success'
        );
        
        // Refresh the list of reports
        await fetchReports();
      } else {
        throw new Error('Invalid response from server: Missing report_id');
      }
      
    } catch (err) {
      if (!isMountedRef.current) return;
      
      console.error('Failed to generate report:', err);
      const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred.';
      
      if (errorMessage.includes('No response received from server') || 
          errorMessage.includes('Network Error') ||
          errorMessage.includes('timeout')) {
        safeSetState(setBackendAvailable, false);
        showNotification('Backend server is not available. Cannot generate reports at this time.', 'error');
      } else {
        showNotification(`Failed to generate report: ${errorMessage}`, 'error');
      }
    } finally {
      if (isMountedRef.current) {
        safeSetState(setIsGenerating, false);
      }
    }
  }, [reportType, startDate, endDate, backendAvailable, safeSetState, showNotification, fetchReports]);

  const handleViewOrDownloadReport = useCallback(async (report: Report | FsReportInfo) => {
    if (!isMountedRef.current) return;
    
    try {
      if (!backendAvailable) {
        showNotification('Cannot access report: Backend server is not available.', 'error');
        return;
      }

      // Check if it's a filesystem report or database report
      const isDbReport = 'report_id' in report;
      const isHtmlReport = report.format === 'html';

      if (isHtmlReport) {
        if (isDbReport) {
          // Database report with file_path
          if (report.file_path && typeof report.file_path === 'string') {
            await open(report.file_path);
            showNotification('Opening HTML report...', 'info');
          } else {
            showNotification('File path not available for this HTML report.', 'error');
          }
        } else {
          // Filesystem report - show in modal
          const fsReport = report as FsReportInfo;
          const reportUrl = reportsApi.getHtmlReportUrl(fsReport.file_name);
          setModalState({
            isOpen: true,
            reportUrl,
            reportTitle: `${fsReport.report_type.charAt(0).toUpperCase() + fsReport.report_type.slice(1)} Report - ${new Date(fsReport.generated_at).toLocaleDateString()}`,
          });
          showNotification('Opening HTML report in modal...', 'info');
        }
      } else {
        // Non-HTML report - download
        if (isDbReport) {
          const dbReport = report as Report;
          try {
            const downloadUrl = reportsApi.getReportDownloadUrl(dbReport.report_id);
            if (downloadUrl && typeof downloadUrl === 'string') {
              window.open(downloadUrl, '_blank');
              showNotification('Downloading report...', 'info');
            } else {
              throw new Error('Invalid download URL');
            }
          } catch (urlError) {
            showNotification('Failed to generate download URL.', 'error');
          }
        } else {
          // Filesystem report - try to open with system default
          const fsReport = report as FsReportInfo;
          try {
            await open(fsReport.file_path);
            showNotification('Opening report with system default application...', 'info');
          } catch (openError) {
            showNotification('Failed to open report file.', 'error');
          }
        }
      }
    } catch (err) {
      console.error('Failed to open or download report:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      showNotification(`Failed to open or download report: ${errorMessage}`, 'error');
    }
  }, [backendAvailable, showNotification]);

  // Close modal function
  const closeModal = useCallback(() => {
    setModalState({
      isOpen: false,
      reportUrl: '',
      reportTitle: '',
    });
  }, []);

  // Safe render with null checks for database reports
  const renderDbReportRow = useCallback((report: Report) => {
    if (!report || typeof report !== 'object') return null;
    
    const reportId = report.report_id || 'Unknown';
    const generatedAt = report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Unknown';
    const reportType = report.report_type || 'Unknown';
    const format = report.format || 'Unknown';
    const status = report.status || 'Unknown';
    
    return (
      <tr key={`db-${reportId}`}>
        <td>{reportId}</td>
        <td>{generatedAt}</td>
        <td>{reportType}</td>
        <td>{format}</td>
        <td>
          <span className={`status-badge status-${status.toLowerCase()}`}>
            {status}
          </span>
        </td>
        <td>📊</td>
        <td>
          <button 
            className="action-button"
            onClick={() => handleViewOrDownloadReport(report)}
            disabled={status !== 'Completed'}
          >
            {report.format === 'html' ? '👁️ View' : '⬇️ Download'}
          </button>
        </td>
      </tr>
    );
  }, [handleViewOrDownloadReport]);

  // Safe render with null checks for filesystem reports
  const renderFsReportRow = useCallback((report: FsReportInfo) => {
    if (!report || typeof report !== 'object') return null;
    
    const fileName = report.file_name || 'Unknown';
    const generatedAt = report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Unknown';
    const reportType = report.report_type || 'Unknown';
    const format = report.format || 'Unknown';
    const fileSizeKB = Math.round(report.file_size / 1024);
    
    return (
      <tr key={`fs-${fileName}`}>
        <td>{fileName}</td>
        <td>{generatedAt}</td>
        <td>{reportType}</td>
        <td>{format}</td>
        <td>
          <span className="status-badge status-completed">
            Completed
          </span>
        </td>
        <td>💾 ({fileSizeKB} KB)</td>
        <td>
          <button 
            className="action-button"
            onClick={() => handleViewOrDownloadReport(report)}
          >
            {report.format === 'html' ? '🖥️ View in Modal' : '📁 Open File'}
          </button>
        </td>
      </tr>
    );
  }, [handleViewOrDownloadReport]);

  return (
    <ErrorBoundary>
      <main className="container reports-page">
        <h1>Generate & View Reports</h1>

        {/* Notification Display */}
        {notification && (
          <div className={`notification notification-${notification.type}`}>
            {notification.message}
            <button 
              className="notification-close"
              onClick={() => safeSetState(setNotification, null)}
            >
              ×
            </button>
          </div>
        )}

        {error && <div className="error-message">{error}</div>}

        {/* Report Generation Section */}
        <section className="report-generator">
          <h2>Generate New Report</h2>
          <div className="report-controls">
            <div className="control-group">
              <label htmlFor="report-type">Report Type:</label>
              <select
                id="report-type"
                value={reportType}
                onChange={(e) => safeSetState(setReportType, e.target.value as ReportTypeOption)}
              >
                <option value="weekly">Weekly Summary</option>
                <option value="monthly">Monthly Analysis</option>
                <option value="incident">Incident Report</option>
                <option value="custom">Custom Date Range</option>
              </select>
            </div>

            {reportType === 'custom' && (
              <>
                <div className="control-group">
                  <label htmlFor="start-date">Start Date:</label>
                  <input
                    type="date"
                    id="start-date"
                    value={startDate}
                    onChange={(e) => safeSetState(setStartDate, e.target.value)}
                  />
                </div>
                <div className="control-group">
                  <label htmlFor="end-date">End Date:</label>
                  <input
                    type="date"
                    id="end-date"
                    value={endDate}
                    onChange={(e) => safeSetState(setEndDate, e.target.value)}
                  />
                </div>
              </>
            )}

            <div className="control-group button-group">
              <button 
                onClick={handleGenerateReport} 
                disabled={
                  isGenerating || 
                  !backendAvailable ||
                  (reportType === 'custom' && (!startDate || !endDate))
                }
              >
                {isGenerating ? 'Generating...' : 'Generate Report'}
              </button>
            </div>
          </div>
        </section>

        {/* Past Reports Section */}
        <section className="past-reports">
          <h2>Past Reports</h2>
          {loading ? (
            <div className="loading-spinner">Loading reports...</div>
          ) : (reports.length === 0 && fsReports.length === 0) && !error ? (
            <p>No reports found.</p>
          ) : (
            <div className="table-responsive">
              <table className="reports-table">
                <thead>
                  <tr>
                    <th>Report ID / File Name</th>
                    <th>Date Generated</th>
                    <th>Type</th>
                    <th>Format</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map(renderDbReportRow)}
                  {fsReports.map(renderFsReportRow)}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* HTML Report Modal */}
        <HtmlReportModal
          isOpen={modalState.isOpen}
          onClose={closeModal}
          reportUrl={modalState.reportUrl}
          reportTitle={modalState.reportTitle}
        />

      </main>
    </ErrorBoundary>
  );
};

export default Reports;
