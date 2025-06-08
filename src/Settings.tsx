import React, { useState, useEffect } from 'react';
import './styles/Settings.css';
import {
  settingsApi,
  GeneralSettings,
  DetectionSettings,
  // Import other specific settings types if you create them in api.ts
  // e.g., NetworkSettings, NotificationSettings
} from './services/api';

// Enhanced interface for local settings
interface EnhancedSettings {
  // General
  emailNotifications: boolean;
  dataRetentionDays: number;
  autoUpdate: boolean;
  language: string;
  theme: 'light' | 'dark' | 'auto';
  
  // Detection
  detectionSensitivity: string;
  enableMachineLearning: boolean;
  enableRealTimeScanning: boolean;
  threatResponseMode: 'automatic' | 'manual' | 'hybrid';
  
  // Network
  enableFirewall: boolean;
  blockSuspiciousIPs: boolean;
  vpnDetection: boolean;
  portScanProtection: boolean;
  ddosProtection: boolean;
  
  // Notifications
  desktopNotifications: boolean;
  soundAlerts: boolean;
  criticalAlertsOnly: boolean;
  notificationVolume: number;
  
  // Advanced
  debugMode: boolean;
  performanceMode: 'balanced' | 'performance' | 'power-saving';
  logLevel: 'error' | 'warning' | 'info' | 'debug';
  maxLogSize: number;
}

const Settings: React.FC = () => {
  // Initialize with default values
  const defaultSettings: EnhancedSettings = {
    emailNotifications: true,
    dataRetentionDays: 30,
    autoUpdate: true,
    language: 'en',
    theme: 'auto',
    detectionSensitivity: 'medium',
    enableMachineLearning: true,
    enableRealTimeScanning: true,
    threatResponseMode: 'hybrid',
    enableFirewall: true,
    blockSuspiciousIPs: true,
    vpnDetection: false,
    portScanProtection: true,
    ddosProtection: true,
    desktopNotifications: true,
    soundAlerts: false,
    criticalAlertsOnly: false,
    notificationVolume: 50,
    debugMode: false,
    performanceMode: 'balanced',
    logLevel: 'warning',
    maxLogSize: 100
  };

  const [settings, setSettings] = useState<EnhancedSettings>(() => {
    // Try to load from localStorage first
    const savedSettings = localStorage.getItem('neurodefender_settings');
    if (savedSettings) {
      try {
        return { ...defaultSettings, ...JSON.parse(savedSettings) };
      } catch (e) {
        console.error('Failed to parse saved settings:', e);
      }
    }
    return defaultSettings;
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'general' | 'detection' | 'network' | 'notifications' | 'advanced'>('general');

  // Load settings when component mounts
  useEffect(() => {
    const loadSettings = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Try to load from API
        try {
          const generalData = await settingsApi.getGeneralSettings();
          const detectionData = await settingsApi.getDetectionSettings();
          
          setSettings(prev => ({
            ...prev,
            emailNotifications: generalData.emailNotifications ?? prev.emailNotifications,
            dataRetentionDays: generalData.dataRetentionDays ?? prev.dataRetentionDays,
            detectionSensitivity: detectionData.detectionSensitivity ?? prev.detectionSensitivity
          }));
        } catch (apiError) {
          console.warn('Using local settings due to API error:', apiError);
          // Continue with local settings
        }
        
        setLoading(false);
      } catch (err) {
        console.error('Failed to load settings:', err);
        setError('Using local settings. Some features may be limited.');
        setLoading(false);
      }
    };
    loadSettings();
  }, []);

  const updateSetting = <K extends keyof EnhancedSettings>(key: K, value: EnhancedSettings[K]) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleSave = async () => {
    try {
      setError(null);
      setSuccessMessage(null);
      setLoading(true);

      // Save to localStorage
      localStorage.setItem('neurodefender_settings', JSON.stringify(settings));

      // Try to save to API
      try {
        const generalSettingsToUpdate: GeneralSettings = {
          emailNotifications: settings.emailNotifications,
          dataRetentionDays: settings.dataRetentionDays,
        };
        await settingsApi.updateGeneralSettings(generalSettingsToUpdate);

        const detectionSettingsToUpdate: DetectionSettings = {
          detectionSensitivity: settings.detectionSensitivity,
        };
        await settingsApi.updateDetectionSettings(detectionSettingsToUpdate);
      } catch (apiError) {
        console.warn('Failed to save to API, but local settings saved:', apiError);
      }
      
      setLoading(false);
      setSuccessMessage('Settings saved successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);

    } catch (err) {
      console.error('Failed to save settings:', err);
      setError('Failed to save some settings. Local settings have been updated.');
      setLoading(false);
    }
  };

  const handleReset = () => {
    if (window.confirm('Are you sure you want to reset all settings to defaults?')) {
      setSettings(defaultSettings);
      localStorage.removeItem('neurodefender_settings');
      setSuccessMessage('Settings reset to defaults');
      setTimeout(() => setSuccessMessage(null), 3000);
    }
  };

  const handleExport = () => {
    const dataStr = JSON.stringify(settings, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `neurodefender_settings_${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const importedSettings = JSON.parse(e.target?.result as string);
          setSettings({ ...defaultSettings, ...importedSettings });
          setSuccessMessage('Settings imported successfully!');
          setTimeout(() => setSuccessMessage(null), 3000);
        } catch (error) {
          setError('Failed to import settings. Invalid file format.');
          setTimeout(() => setError(null), 3000);
        }
      };
      reader.readAsText(file);
    }
  };

  if (loading && !error) {
    return <div className="loading-spinner">Loading settings...</div>;
  }

  return (
    <>
      <main className="container">
        <div className="settings-header">
          <h1>System Settings</h1>
          <div className="settings-actions-top">
            <button className="secondary-button" onClick={handleExport}>
              Export Settings
            </button>
            <label className="secondary-button">
              Import Settings
              <input type="file" accept=".json" onChange={handleImport} style={{ display: 'none' }} />
            </label>
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}
        {successMessage && <div className="success-message">{successMessage}</div>}

        <div className="settings-tabs">
          <button 
            className={`tab ${activeTab === 'general' ? 'active' : ''}`}
            onClick={() => setActiveTab('general')}
          >
            General
          </button>
          <button 
            className={`tab ${activeTab === 'detection' ? 'active' : ''}`}
            onClick={() => setActiveTab('detection')}
          >
            Detection
          </button>
          <button 
            className={`tab ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => setActiveTab('network')}
          >
            Network
          </button>
          <button 
            className={`tab ${activeTab === 'notifications' ? 'active' : ''}`}
            onClick={() => setActiveTab('notifications')}
          >
            Notifications
          </button>
          <button 
            className={`tab ${activeTab === 'advanced' ? 'active' : ''}`}
            onClick={() => setActiveTab('advanced')}
          >
            Advanced
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'general' && (
            <section className="settings-section">
              <h2>General Settings</h2>
              
              <div className="setting-item">
                <label htmlFor="theme">Application Theme:</label>
                <select
                  id="theme"
                  value={settings.theme}
                  onChange={(e) => updateSetting('theme', e.target.value as 'light' | 'dark' | 'auto')}
                  disabled={loading}
                >
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                  <option value="auto">Auto (System)</option>
                </select>
              </div>

              <div className="setting-item">
                <label htmlFor="language">Language:</label>
                <select
                  id="language"
                  value={settings.language}
                  onChange={(e) => updateSetting('language', e.target.value)}
                  disabled={loading}
                >
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                  <option value="de">German</option>
                  <option value="ja">Japanese</option>
                </select>
              </div>

              <div className="setting-item">
                <label htmlFor="auto-update">
                  <input
                    type="checkbox"
                    id="auto-update"
                    checked={settings.autoUpdate}
                    onChange={(e) => updateSetting('autoUpdate', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Automatic Updates
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="data-retention">Data Retention Period (days):</label>
                <input
                  type="number"
                  id="data-retention"
                  value={settings.dataRetentionDays}
                  onChange={(e) => updateSetting('dataRetentionDays', parseInt(e.target.value, 10) || 0)}
                  min="1"
                  max="365"
                  disabled={loading}
                />
              </div>
            </section>
          )}

          {activeTab === 'detection' && (
            <section className="settings-section">
              <h2>Detection Settings</h2>
              
              <div className="setting-item">
                <label htmlFor="detection-sensitivity">Detection Sensitivity:</label>
                <select
                  id="detection-sensitivity"
                  value={settings.detectionSensitivity}
                  onChange={(e) => updateSetting('detectionSensitivity', e.target.value)}
                  disabled={loading}
                >
                  <option value="low">Low - Fewer false positives</option>
                  <option value="medium">Medium - Balanced</option>
                  <option value="high">High - Maximum protection</option>
                </select>
              </div>

              <div className="setting-item">
                <label htmlFor="ml-detection">
                  <input
                    type="checkbox"
                    id="ml-detection"
                    checked={settings.enableMachineLearning}
                    onChange={(e) => updateSetting('enableMachineLearning', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Machine Learning Detection
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="realtime-scan">
                  <input
                    type="checkbox"
                    id="realtime-scan"
                    checked={settings.enableRealTimeScanning}
                    onChange={(e) => updateSetting('enableRealTimeScanning', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Real-time Scanning
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="threat-response">Threat Response Mode:</label>
                <select
                  id="threat-response"
                  value={settings.threatResponseMode}
                  onChange={(e) => updateSetting('threatResponseMode', e.target.value as 'automatic' | 'manual' | 'hybrid')}
                  disabled={loading}
                >
                  <option value="automatic">Automatic - Block threats immediately</option>
                  <option value="manual">Manual - Alert only</option>
                  <option value="hybrid">Hybrid - Auto-block high severity only</option>
                </select>
              </div>
            </section>
          )}

          {activeTab === 'network' && (
            <section className="settings-section">
              <h2>Network Protection</h2>
              
              <div className="setting-item">
                <label htmlFor="firewall">
                  <input
                    type="checkbox"
                    id="firewall"
                    checked={settings.enableFirewall}
                    onChange={(e) => updateSetting('enableFirewall', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Firewall Protection
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="block-ips">
                  <input
                    type="checkbox"
                    id="block-ips"
                    checked={settings.blockSuspiciousIPs}
                    onChange={(e) => updateSetting('blockSuspiciousIPs', e.target.checked)}
                    disabled={loading}
                  />
                  Automatically Block Suspicious IPs
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="vpn-detection">
                  <input
                    type="checkbox"
                    id="vpn-detection"
                    checked={settings.vpnDetection}
                    onChange={(e) => updateSetting('vpnDetection', e.target.checked)}
                    disabled={loading}
                  />
                  Enable VPN Detection
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="port-scan">
                  <input
                    type="checkbox"
                    id="port-scan"
                    checked={settings.portScanProtection}
                    onChange={(e) => updateSetting('portScanProtection', e.target.checked)}
                    disabled={loading}
                  />
                  Port Scan Protection
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="ddos-protection">
                  <input
                    type="checkbox"
                    id="ddos-protection"
                    checked={settings.ddosProtection}
                    onChange={(e) => updateSetting('ddosProtection', e.target.checked)}
                    disabled={loading}
                  />
                  DDoS Protection
                </label>
              </div>
            </section>
          )}

          {activeTab === 'notifications' && (
            <section className="settings-section">
              <h2>Notification Preferences</h2>
              
              <div className="setting-item">
                <label htmlFor="email-notifications">
                  <input
                    type="checkbox"
                    id="email-notifications"
                    checked={settings.emailNotifications}
                    onChange={(e) => updateSetting('emailNotifications', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Email Notifications
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="desktop-notifications">
                  <input
                    type="checkbox"
                    id="desktop-notifications"
                    checked={settings.desktopNotifications}
                    onChange={(e) => updateSetting('desktopNotifications', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Desktop Notifications
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="sound-alerts">
                  <input
                    type="checkbox"
                    id="sound-alerts"
                    checked={settings.soundAlerts}
                    onChange={(e) => updateSetting('soundAlerts', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Sound Alerts
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="critical-only">
                  <input
                    type="checkbox"
                    id="critical-only"
                    checked={settings.criticalAlertsOnly}
                    onChange={(e) => updateSetting('criticalAlertsOnly', e.target.checked)}
                    disabled={loading}
                  />
                  Critical Alerts Only
                </label>
              </div>

              <div className="setting-item">
                <label htmlFor="volume">Notification Volume: {settings.notificationVolume}%</label>
                <input
                  type="range"
                  id="volume"
                  min="0"
                  max="100"
                  value={settings.notificationVolume}
                  onChange={(e) => updateSetting('notificationVolume', parseInt(e.target.value, 10))}
                  disabled={loading || !settings.soundAlerts}
                />
              </div>
            </section>
          )}

          {activeTab === 'advanced' && (
            <section className="settings-section">
              <h2>Advanced Settings</h2>
              
              <div className="setting-item">
                <label htmlFor="performance-mode">Performance Mode:</label>
                <select
                  id="performance-mode"
                  value={settings.performanceMode}
                  onChange={(e) => updateSetting('performanceMode', e.target.value as 'balanced' | 'performance' | 'power-saving')}
                  disabled={loading}
                >
                  <option value="balanced">Balanced</option>
                  <option value="performance">High Performance</option>
                  <option value="power-saving">Power Saving</option>
                </select>
              </div>

              <div className="setting-item">
                <label htmlFor="log-level">Log Level:</label>
                <select
                  id="log-level"
                  value={settings.logLevel}
                  onChange={(e) => updateSetting('logLevel', e.target.value as 'error' | 'warning' | 'info' | 'debug')}
                  disabled={loading}
                >
                  <option value="error">Errors Only</option>
                  <option value="warning">Warnings & Errors</option>
                  <option value="info">Info & Above</option>
                  <option value="debug">Debug (All)</option>
                </select>
              </div>

              <div className="setting-item">
                <label htmlFor="max-log-size">Max Log Size (MB):</label>
                <input
                  type="number"
                  id="max-log-size"
                  value={settings.maxLogSize}
                  onChange={(e) => updateSetting('maxLogSize', parseInt(e.target.value, 10) || 100)}
                  min="10"
                  max="1000"
                  disabled={loading}
                />
              </div>

              <div className="setting-item">
                <label htmlFor="debug-mode">
                  <input
                    type="checkbox"
                    id="debug-mode"
                    checked={settings.debugMode}
                    onChange={(e) => updateSetting('debugMode', e.target.checked)}
                    disabled={loading}
                  />
                  Enable Debug Mode
                </label>
              </div>
            </section>
          )}
        </div>

        <div className="settings-actions">
          <button onClick={handleSave} disabled={loading} className="primary-button">
            {loading ? 'Saving...' : 'Save Settings'}
          </button>
          <button onClick={handleReset} disabled={loading} className="secondary-button">
            Reset to Defaults
          </button>
        </div>

      </main>
    </>
  );
};

export default Settings;
