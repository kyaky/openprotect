//! System tray icon management.

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// Create a 32x32 icon with a colored circle.
fn make_circle_icon(r: u8, g: u8, b: u8) -> Icon {
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    let radius = center - 2.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= radius {
                rgba.extend_from_slice(&[r, g, b, 255]);
            } else if dist <= radius + 1.0 {
                let alpha = ((radius + 1.0 - dist) * 255.0) as u8;
                rgba.extend_from_slice(&[r, g, b, alpha]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    Icon::from_rgba(rgba, size, size).expect("failed to create icon")
}

pub struct IconSet {
    pub connected: Icon,
    pub disconnected: Icon,
    pub connecting: Icon,
}

impl IconSet {
    pub fn new() -> Self {
        Self {
            connected: make_circle_icon(34, 197, 94),
            disconnected: make_circle_icon(239, 68, 68),
            connecting: make_circle_icon(234, 179, 8),
        }
    }
}

pub struct TrayMenuIds {
    pub show_id: tray_icon::menu::MenuId,
    pub exit_id: tray_icon::menu::MenuId,
}

/// Build the system tray icon and menu. Returns the tray and menu IDs.
pub fn build(icons: &IconSet) -> (TrayIcon, TrayMenuIds) {
    let menu = Menu::new();
    let item_show = MenuItem::new("Show OpenProtect", true, None);
    let item_exit = MenuItem::new("Exit", true, None);

    let show_id = item_show.id().clone();
    let exit_id = item_exit.id().clone();

    menu.append(&item_show).ok();
    menu.append(&PredefinedMenuItem::separator()).ok();
    menu.append(&item_exit).ok();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("OpenProtect — Disconnected")
        .with_icon(icons.disconnected.clone())
        .build()
        .expect("failed to create tray icon");

    let ids = TrayMenuIds { show_id, exit_id };
    (tray, ids)
}

/// Update the tray icon and tooltip based on VPN state.
pub fn update_state(tray: &TrayIcon, icons: &IconSet, state: &crate::opc::VpnState) {
    match state {
        crate::opc::VpnState::Connected(info) => {
            let _ = tray.set_icon(Some(icons.connected.clone()));
            let tooltip = format!(
                "OpenProtect -- Connected\n{} via {}\nIP: {}",
                info.user,
                info.gateway,
                info.local_ipv4.as_deref().unwrap_or("?"),
            );
            let _ = tray.set_tooltip(Some(&tooltip));
        }
        crate::opc::VpnState::Connecting => {
            let _ = tray.set_icon(Some(icons.connecting.clone()));
            let _ = tray.set_tooltip(Some("OpenProtect -- Connecting..."));
        }
        crate::opc::VpnState::Disconnected => {
            let _ = tray.set_icon(Some(icons.disconnected.clone()));
            let _ = tray.set_tooltip(Some("OpenProtect -- Disconnected"));
        }
    }
}

/// Check for tray menu events. Returns action if any.
pub enum TrayAction {
    Show,
    Exit,
}

pub fn poll_menu(ids: &TrayMenuIds) -> Option<TrayAction> {
    let mut action = None;

    // Drain all pending tray icon events.
    while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
        if matches!(ev, TrayIconEvent::DoubleClick { .. }) {
            action = Some(TrayAction::Show);
        }
    }

    // Drain all pending menu events.
    while let Ok(ev) = MenuEvent::receiver().try_recv() {
        if ev.id() == &ids.show_id {
            action = Some(TrayAction::Show);
        }
        if ev.id() == &ids.exit_id {
            action = Some(TrayAction::Exit);
        }
    }

    action
}
