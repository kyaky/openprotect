//! `pgn-tray` — Pangolin system tray application.
//!
//! Minimal GUI wrapper around the `pgn` CLI. Shows a colored tray
//! icon (green/yellow/red) and provides Connect/Disconnect/Status
//! via right-click menu. Works on Windows, macOS, and Linux.

mod icons;
mod pgn;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::TrayIconBuilder;

/// Custom event posted from the status-polling thread.
#[derive(Debug, Clone)]
enum UserEvent {
    StatusChanged(pgn::VpnState),
}

fn main() {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    // Build the right-click menu.
    let menu = Menu::new();
    let item_connect = MenuItem::new("Connect", true, None);
    let item_disconnect = MenuItem::new("Disconnect", true, None);
    let item_status = MenuItem::new("Status: Disconnected", false, None);
    let item_separator = PredefinedMenuItem::separator();
    let item_exit = MenuItem::new("Exit", true, None);

    let connect_id = item_connect.id().clone();
    let disconnect_id = item_disconnect.id().clone();
    let exit_id = item_exit.id().clone();
    menu.append(&item_status).ok();
    menu.append(&item_separator).ok();
    menu.append(&item_connect).ok();
    menu.append(&item_disconnect).ok();
    menu.append(&PredefinedMenuItem::separator()).ok();
    menu.append(&item_exit).ok();

    // Create the tray icon.
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Pangolin — Disconnected")
        .with_icon(icons::disconnected())
        .build()
        .expect("failed to create tray icon");

    // Share the tray icon handle for updates from the polling thread.
    let tray = Arc::new(Mutex::new(_tray));

    // Clone references for the menu item text updates.
    let status_item = Arc::new(Mutex::new(item_status));

    // Status polling thread.
    let proxy = event_loop.create_proxy();
    let mut last_key = String::new();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3));
        let state = pgn::poll_status();
        // Compare a stable subset — exclude uptime which changes every poll.
        let key = match &state {
            pgn::VpnState::Connected(info) => {
                format!(
                    "connected:{}:{}",
                    info.gateway,
                    info.local_ipv4.as_deref().unwrap_or("")
                )
            }
            pgn::VpnState::Connecting => "connecting".to_string(),
            pgn::VpnState::Disconnected => "disconnected".to_string(),
        };
        if key != last_key {
            last_key = key;
            let _ = proxy.send_event(UserEvent::StatusChanged(state));
        }
    });

    // Menu event receiver.
    let menu_rx = MenuEvent::receiver();

    // Run the event loop.
    event_loop.run(move |event, _, control_flow| {
        *control_flow =
            ControlFlow::WaitUntil(std::time::Instant::now() + Duration::from_millis(100));

        // Handle menu clicks.
        if let Ok(event) = menu_rx.try_recv() {
            if event.id() == &connect_id {
                // TODO: let user pick profile. For now, connect default.
                pgn::connect("");
            } else if event.id() == &disconnect_id {
                pgn::disconnect();
            } else if event.id() == &exit_id {
                *control_flow = ControlFlow::Exit;
            }
        }

        // Handle status updates from polling thread.
        if let Event::UserEvent(UserEvent::StatusChanged(ref state)) = event {
            let Ok(tray) = tray.lock() else { return };
            let Ok(status_item) = status_item.lock() else {
                return;
            };

            match state {
                pgn::VpnState::Connected(info) => {
                    let _ = tray.set_icon(Some(icons::connected()));
                    let tooltip = format!(
                        "Pangolin — Connected\n{} via {}\nIP: {}",
                        info.user,
                        info.gateway,
                        info.local_ipv4.as_deref().unwrap_or("?"),
                    );
                    let _ = tray.set_tooltip(Some(&tooltip));
                    let text = format!(
                        "Connected: {} ({})",
                        info.gateway,
                        info.local_ipv4.as_deref().unwrap_or("?")
                    );
                    status_item.set_text(&text);
                }
                pgn::VpnState::Connecting => {
                    let _ = tray.set_icon(Some(icons::connecting()));
                    let _ = tray.set_tooltip(Some("Pangolin — Connecting..."));
                    status_item.set_text("Status: Connecting...");
                }
                pgn::VpnState::Disconnected => {
                    let _ = tray.set_icon(Some(icons::disconnected()));
                    let _ = tray.set_tooltip(Some("Pangolin — Disconnected"));
                    status_item.set_text("Status: Disconnected");
                }
            }
        }
    });
}
