use tauri::{AppHandle, Runtime, Manager, Emitter, Listener};
use log::{info, error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPayload {
    pub title: String,
    pub body: String,
    pub icon: Option<String>,
}

/// Send a system notification by emitting an event
pub fn send_notification<R: Runtime>(
    app: &AppHandle<R>,
    title: impl Into<String>,
    body: impl Into<String>,
) -> tauri::Result<()> {
    let title = title.into();
    let body = body.into();
    
    info!("Sending notification: {} - {}", title, body);
    
    // Emit an event that the frontend can handle to show notifications
    app.emit("system-notification", NotificationPayload {
        title,
        body,
        icon: None,
    })?;
    
    Ok(())
}

/// Set up listener for notification requests from frontend
pub fn setup_notification_listener<R: Runtime>(app: AppHandle<R>) -> tauri::Result<()> {
    let app_clone = app.clone();
    app.listen("tray-notification", move |event| {
        if let Ok(payload) = serde_json::from_str::<NotificationPayload>(event.payload()) {
            if let Err(e) = send_notification(&app_clone, payload.title, payload.body) {
                error!("Failed to send notification: {}", e);
            }
        }
    });
    
    Ok(())
}

/// Send alert notification
pub fn send_alert_notification<R: Runtime>(
    app: &AppHandle<R>,
    severity: &str,
    description: &str,
) -> tauri::Result<()> {
    let title = format!("NeuroDefender - {} Alert", severity);
    send_notification(app, title, description)
}

/// Send monitoring status notification
pub fn send_status_notification<R: Runtime>(
    app: &AppHandle<R>,
    is_active: bool,
) -> tauri::Result<()> {
    let (title, body) = if is_active {
        ("NeuroDefender - Monitoring Started", "Network monitoring is now active")
    } else {
        ("NeuroDefender - Monitoring Stopped", "Network monitoring has been stopped")
    };
    
    send_notification(app, title, body)
} 