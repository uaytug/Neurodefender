use tauri::{
    menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, Runtime, AppHandle, Listener,
};
use tauri_plugin_autostart::AutoLaunchManager;
use log::{info, error, warn};
use serde::{Deserialize, Serialize};
use crate::tray_module::notifications::{setup_notification_listener, send_status_notification};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayState {
    pub is_monitoring: bool,
    pub alert_count: u32,
    pub cpu_usage: f64,
    pub memory_usage: f64,
}

pub fn init_tray<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    /* ───────── window ───────── */
    let show_i = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
    let hide_i = MenuItem::with_id(app, "hide", "Hide window", true, None::<&str>)?;
    let separator1 = PredefinedMenuItem::separator(app)?;

    /* ───────── IDPS actions ─── */
    let start_i  = MenuItem::with_id(app, "start",  "Start Monitoring", true, None::<&str>)?;
    let stop_i   = MenuItem::with_id(app, "stop",   "Stop Monitoring",  true, None::<&str>)?;
    let separator2 = PredefinedMenuItem::separator(app)?;
    
    let alerts_i = MenuItem::with_id(app, "alerts", "View Alerts", true, None::<&str>)?;
    let rules_i  = MenuItem::with_id(app, "rules",  "Manage Rules", true, None::<&str>)?;
    let reports_i = MenuItem::with_id(app, "reports", "View Reports", true, None::<&str>)?;
    let separator3 = PredefinedMenuItem::separator(app)?;

    /* ───────── Status submenu ───── */
    let status_monitoring = MenuItem::with_id(app, "status_monitoring", "Monitoring: Active", false, None::<&str>)?;
    let status_alerts = MenuItem::with_id(app, "status_alerts", "Alerts: 0 unread", false, None::<&str>)?;
    let status_cpu = MenuItem::with_id(app, "status_cpu", "CPU: 0%", false, None::<&str>)?;
    let status_memory = MenuItem::with_id(app, "status_memory", "Memory: 0%", false, None::<&str>)?;
    
    let status_submenu = Submenu::with_items(
        app,
        "System Status",
        true,
        &[
            &status_monitoring.clone(),
            &status_alerts.clone(),
            &status_cpu.clone(),
            &status_memory.clone(),
        ],
    )?;
    let separator4 = PredefinedMenuItem::separator(app)?;

    /* ───────── settings / autostart ───── */
    let autostart_state = app.state::<AutoLaunchManager>();
    let autostart_checked = autostart_state
        .is_enabled()
        .unwrap_or(false);

    let settings_i = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let autostart_i = CheckMenuItem::with_id(
        app,
        "autostart",
        "Launch at Login",
        autostart_checked,
        true,
        None::<&str>,
    )?;
    let separator5 = PredefinedMenuItem::separator(app)?;

    /* ───────── about / quit ─────────── */
    let about_i = MenuItem::with_id(app, "about", "About NeuroDefender", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    /* ───────── build menu ───── */
    let menu = Menu::with_items(
        app,
        &[
            &show_i,
            &hide_i,
            &separator1,
            &start_i,
            &stop_i,
            &separator2,
            &alerts_i,
            &rules_i,
            &reports_i,
            &separator3,
            &status_submenu,
            &separator4,
            &settings_i,
            &autostart_i,
            &separator5,
            &about_i,
            &quit_i,
        ],
    )?;

    // Keep handles for dynamic updates
    let autostart_item_handle = autostart_i.clone();
    let start_handle = start_i.clone();
    let stop_handle = stop_i.clone();
    let status_monitoring_handle = status_monitoring.clone();
    let status_alerts_handle = status_alerts.clone();
    let status_cpu_handle = status_cpu.clone();
    let status_memory_handle = status_memory.clone();

    // Set initial state
    start_handle.set_enabled(true)?;
    stop_handle.set_enabled(false)?;

    TrayIconBuilder::with_id("neuro_tray")
        .tooltip("NeuroDefender - Network Security Monitor")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .show_menu_on_left_click(false)
        /* ───────── menu clicks ───────── */
        .on_menu_event(move |app, event| match event.id.as_ref() {
            /* window control */
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "hide" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            /* IDPS actions (emit to frontend) */
            "start" => {
                info!("Starting monitoring from tray");
                let _ = app.emit("idps-start", ());
                // Update menu state
                let _ = start_handle.set_enabled(false);
                let _ = stop_handle.set_enabled(true);
                let _ = status_monitoring_handle.set_text("Monitoring: Active");
                // Send notification
                let _ = send_status_notification(app, true);
            }
            "stop" => {
                info!("Stopping monitoring from tray");
                let _ = app.emit("idps-stop", ());
                // Update menu state
                let _ = start_handle.set_enabled(true);
                let _ = stop_handle.set_enabled(false);
                let _ = status_monitoring_handle.set_text("Monitoring: Inactive");
                // Send notification
                let _ = send_status_notification(app, false);
            }
            "alerts" => {
                let _ = app.emit("open-alerts", ());
                // Also show window
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "rules" => {
                let _ = app.emit("open-rules", ());
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "reports" => {
                let _ = app.emit("open-reports", ());
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }

            /* settings window */
            "settings" => {
                let _ = app.emit("open-settings", ());
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }

            /* autostart toggle */
            "autostart" => {
                let mgr = app.state::<AutoLaunchManager>();
                let now_enabled = mgr.is_enabled().unwrap_or(false);
                if now_enabled {
                    match mgr.disable() {
                        Ok(_) => {
                            info!("Autostart disabled");
                            let _ = autostart_item_handle.set_checked(false);
                        }
                        Err(e) => error!("Failed to disable autostart: {}", e),
                    }
                } else {
                    match mgr.enable() {
                        Ok(_) => {
                            info!("Autostart enabled");
                            let _ = autostart_item_handle.set_checked(true);
                        }
                        Err(e) => error!("Failed to enable autostart: {}", e),
                    }
                }
            }

            /* about */
            "about" => {
                let _ = app.emit("open-about", ());
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }

            /* quit */
            "quit" => {
                info!("Quitting application from tray");
                app.exit(0);
            }
            _ => {}
        })
        /* ───────── tray icon left-click toggles main window ───────── */
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("main") {
                    if win.is_visible().unwrap_or(false) {
                        let _ = win.hide();
                    } else {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    // Set up event listener for dynamic tray updates
    setup_tray_update_listener(app.clone(), status_alerts_handle, status_cpu_handle, status_memory_handle)?;
    
    // Set up notification listener
    setup_notification_listener(app.clone())?;

    Ok(())
}

// Function to handle dynamic tray updates from frontend
fn setup_tray_update_listener<R: Runtime>(
    app: AppHandle<R>,
    status_alerts: MenuItem<R>,
    status_cpu: MenuItem<R>,
    status_memory: MenuItem<R>,
) -> tauri::Result<()> {
    let app_handle = app.clone();
    
    app.listen("update-tray-state", move |event| {
        if let Ok(state) = serde_json::from_str::<TrayState>(event.payload()) {
            // Update alert count
            let alert_text = format!("Alerts: {} unread", state.alert_count);
            let _ = status_alerts.set_text(&alert_text);
            
            // Update CPU usage
            let cpu_text = format!("CPU: {:.1}%", state.cpu_usage);
            let _ = status_cpu.set_text(&cpu_text);
            
            // Update memory usage
            let memory_text = format!("Memory: {:.1}%", state.memory_usage);
            let _ = status_memory.set_text(&memory_text);
            
            // Update tooltip
            let tooltip = format!(
                "NeuroDefender\n{}\nCPU: {:.1}% | Memory: {:.1}%",
                if state.is_monitoring { "Monitoring Active" } else { "Monitoring Inactive" },
                state.cpu_usage,
                state.memory_usage
            );
            
            if let Some(tray) = app_handle.tray_by_id("neuro_tray") {
                let _ = tray.set_tooltip(Some(&tooltip));
            }
        }
    });
    
    Ok(())
}
