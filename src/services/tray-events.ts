import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { settingsApi } from './api';
import { getCurrentWindow } from '@tauri-apps/api/window';

// Event listener for tray menu actions
export function useTrayEventListeners() {
  const navigate = useNavigate();

  useEffect(() => {
    // Keep track of unlisteners to clean up
    const unlisteners: Array<() => void> = [];

    // Start monitoring event
    const setupListeners = async () => {
      unlisteners.push(await listen('idps-start', async () => {
        console.log('Starting monitoring from tray...');
        try {
          // Call your API to start monitoring
          // Setting high sensitivity when starting from tray
          await settingsApi.updateDetectionSettings({ detectionSensitivity: 'high' });
          console.log('Monitoring started successfully');
        } catch (error) {
          console.error('Failed to start monitoring:', error);
        }
      }));

      // Stop monitoring event
      unlisteners.push(await listen('idps-stop', async () => {
        console.log('Stopping monitoring from tray...');
        try {
          // Call your API to stop monitoring
          // Setting low sensitivity as a way to "stop" monitoring
          await settingsApi.updateDetectionSettings({ detectionSensitivity: 'low' });
          console.log('Monitoring stopped successfully');
        } catch (error) {
          console.error('Failed to stop monitoring:', error);
        }
      }));

      // Open alerts page
      unlisteners.push(await listen('open-alerts', async () => {
        console.log('Opening alerts from tray...');
        navigate('/alerts');
        // Ensure window is visible
        const currentWindow = getCurrentWindow();
        await currentWindow.show();
        await currentWindow.setFocus();
      }));

      // Open rules/settings page
      unlisteners.push(await listen('open-rules', async () => {
        console.log('Opening rules from tray...');
        navigate('/settings');
        // Ensure window is visible
        const currentWindow = getCurrentWindow();
        await currentWindow.show();
        await currentWindow.setFocus();
      }));

      // Open settings page
      unlisteners.push(await listen('open-settings', async () => {
        console.log('Opening settings from tray...');
        navigate('/settings');
        // Ensure window is visible
        const currentWindow = getCurrentWindow();
        await currentWindow.show();
        await currentWindow.setFocus();
      }));

      // Open reports page
      unlisteners.push(await listen('open-reports', async () => {
        console.log('Opening reports from tray...');
        navigate('/reports');
        // Ensure window is visible
        const currentWindow = getCurrentWindow();
        await currentWindow.show();
        await currentWindow.setFocus();
      }));

      // Open about dialog or navigate to FAQ
      unlisteners.push(await listen('open-about', async () => {
        console.log('Opening about from tray...');
        navigate('/faq');
        // Ensure window is visible
        const currentWindow = getCurrentWindow();
        await currentWindow.show();
        await currentWindow.setFocus();
      }));

      // Backend health status updates
      unlisteners.push(await listen('backend-health-status', (event) => {
        console.log('Backend health status:', event.payload);
        // You could update some global state here to show backend status in UI
      }));

      // Backend critical error
      unlisteners.push(await listen('backend-critical-error', (event) => {
        console.error('Backend critical error:', event.payload);
        // Show user notification about backend failure
      }));

      // System notifications
      unlisteners.push(await listen('system-notification', (event: any) => {
        console.log('System notification:', event.payload);
        const { title, body } = event.payload;
        
        // Show browser notification if permissions are granted
        if ('Notification' in window && Notification.permission === 'granted') {
          new Notification(title, {
            body,
            icon: '/neurodefender_logo.png',
          });
        } else if ('Notification' in window && Notification.permission !== 'denied') {
          // Request permission if not already denied
          Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
              new Notification(title, {
                body,
                icon: '/neurodefender_logo.png',
              });
            }
          });
        }
      }));
    };

    setupListeners();

    // Cleanup on unmount
    return () => {
      unlisteners.forEach(unlisten => unlisten());
    };
  }, [navigate]);
}

// Function to emit events to the tray
export async function updateTrayState(state: {
  isMonitoring?: boolean;
  alertCount?: number;
  cpuUsage?: number;
  memoryUsage?: number;
}) {
  try {
    const { emit } = await import('@tauri-apps/api/event');
    await emit('update-tray-state', state);
  } catch (error) {
    console.error('Failed to update tray state:', error);
  }
}

// Function to send notification through system tray
export async function sendTrayNotification(title: string, body: string) {
  try {
    const { emit } = await import('@tauri-apps/api/event');
    await emit('tray-notification', { title, body });
  } catch (error) {
    console.error('Failed to send tray notification:', error);
  }
} 