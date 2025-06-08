use tauri::{AppHandle, Manager, Result, WebviewUrl, WebviewWindowBuilder};

pub fn show_popup(app: &AppHandle) -> Result<()> {
    const LABEL: &str = "popup";

    if let Some(w) = app.get_webview_window(LABEL) {
        w.show()?; w.set_focus()?;
        return Ok(());
    }

    WebviewWindowBuilder::new(
        app,
        LABEL,
        // 👇 Must match the filename you just created
        WebviewUrl::App("popup.html".into()),
    )
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .inner_size(380.0, 220.0)
        .build()?;

    Ok(())
}
