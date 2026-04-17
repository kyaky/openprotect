//! `opc-gui` — OpenProtect desktop GUI for GlobalProtect VPN.
//!
//! Built with egui/eframe. Provides a system tray icon plus a full
//! windowed interface for connect/disconnect, status, logs, and about.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod opc;
mod theme;
mod tray;
mod views;

use std::time::{Duration, Instant};

use eframe::egui;

use views::AppState;

fn main() -> eframe::Result<()> {
    // Build tray icon before eframe takes over the event loop.
    let icons = tray::IconSet::new();
    let (tray_icon, tray_ids) = tray::build(&icons);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("OpenProtect")
            .with_inner_size([460.0, 560.0])
            .with_min_inner_size([380.0, 440.0])
            .with_close_button(true),
        ..Default::default()
    };

    eframe::run_native(
        "OpenProtect",
        options,
        Box::new(move |cc| {
            // Apply custom theme.
            theme::apply(&cc.egui_ctx);

            // Restore persisted state or use defaults.
            let state: AppState = cc
                .storage
                .and_then(|s| eframe::get_value(s, eframe::APP_KEY))
                .unwrap_or_default();

            Ok(Box::new(OpenProtectApp {
                state,
                tray_icon,
                tray_ids,
                icons,
                last_poll: Instant::now() - Duration::from_secs(10), // poll immediately
                wants_exit: false,
            }))
        }),
    )
}

struct OpenProtectApp {
    state: AppState,
    tray_icon: tray_icon::TrayIcon,
    tray_ids: tray::TrayMenuIds,
    icons: tray::IconSet,
    last_poll: Instant,
    /// True only when the user clicks "Exit" from the tray menu.
    wants_exit: bool,
}

impl eframe::App for OpenProtectApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.state);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Intercept the window close button → hide to tray instead.
        if ctx.input(|i| i.viewport().close_requested()) && !self.wants_exit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Poll VPN status every 3 seconds.
        if self.last_poll.elapsed() >= Duration::from_secs(3) {
            self.last_poll = Instant::now();
            let new_state = opc::poll_status();

            // Track connect time.
            if matches!(new_state, opc::VpnState::Connected(_))
                && self.state.connect_time.is_none()
            {
                self.state.connect_time = Some(Instant::now());
            } else if matches!(new_state, opc::VpnState::Disconnected) {
                self.state.connect_time = None;
            }

            // Reset connect guard if the thread signalled completion.
            if self
                .state
                .connect_done
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                self.state.connect_in_flight = false;
            }

            if new_state != self.state.vpn_state {
                tray::update_state(&self.tray_icon, &self.icons, &new_state);
                self.state.vpn_state = new_state;
            }
        }

        // Handle tray menu events.
        if let Some(action) = tray::poll_menu(&self.tray_ids) {
            match action {
                tray::TrayAction::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                tray::TrayAction::Exit => {
                    // Real exit — set the flag so the close isn't intercepted.
                    self.wants_exit = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        // Request repaint every 500ms for status updates.
        ctx.request_repaint_after(Duration::from_millis(500));

        // Draw UI.
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(160.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::BG_SECONDARY)
                    .inner_margin(12.0),
            )
            .show(ctx, |ui| {
                views::sidebar(ui, &mut self.state);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG_PRIMARY)
                    .inner_margin(24.0),
            )
            .show(ctx, |ui| match self.state.active_tab {
                views::Tab::Connect => views::connect_view(ui, &mut self.state),
                views::Tab::Logs => views::log_view(ui, &mut self.state),
                views::Tab::About => views::about_view(ui),
            });
    }
}
