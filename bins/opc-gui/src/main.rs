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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use eframe::egui;

use views::AppState;

/// Whether the window is currently visible.
static VISIBLE: Mutex<bool> = Mutex::new(true);
/// Tray → UI: request exit.
static TRAY_EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Raw HWND stored as isize for cross-thread use.
#[cfg(windows)]
static STORED_HWND: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

#[cfg(windows)]
fn toggle_window() {
    let hwnd = STORED_HWND.load(Ordering::SeqCst);
    if hwnd == 0 {
        return;
    }
    let h = hwnd as windows_sys::Win32::Foundation::HWND;
    let mut visible = VISIBLE.lock().unwrap();
    unsafe {
        if *visible {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                h,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
            );
            *visible = false;
        } else {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                h,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT,
            );
            windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow(h);
            *visible = true;
        }
    }
}

#[cfg(windows)]
fn show_window_force() {
    let hwnd = STORED_HWND.load(Ordering::SeqCst);
    if hwnd == 0 {
        return;
    }
    let h = hwnd as windows_sys::Win32::Foundation::HWND;
    let mut visible = VISIBLE.lock().unwrap();
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
            h,
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT,
        );
        windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow(h);
    }
    *visible = true;
}

#[cfg(windows)]
fn hide_window() {
    let hwnd = STORED_HWND.load(Ordering::SeqCst);
    if hwnd == 0 {
        return;
    }
    let h = hwnd as windows_sys::Win32::Foundation::HWND;
    let mut visible = VISIBLE.lock().unwrap();
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
            h,
            windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
        );
    }
    *visible = false;
}

#[cfg(not(windows))]
fn toggle_window() {}
#[cfg(not(windows))]
fn show_window_force() {}
#[cfg(not(windows))]
fn hide_window() {}

fn main() -> eframe::Result<()> {
    let icons = tray::IconSet::new();
    let (tray_icon, tray_ids) = tray::build(&icons);

    // Set up tray icon event handler — this callback fires on the
    // correct thread context, so ShowWindow works directly.
    tray_icon::TrayIconEvent::set_event_handler(Some(move |event: tray_icon::TrayIconEvent| {
        if matches!(
            event,
            tray_icon::TrayIconEvent::DoubleClick {
                button: tray_icon::MouseButton::Left,
                ..
            }
        ) {
            toggle_window();
        }
    }));

    // Menu events (Show / Exit) — also use set_event_handler.
    let show_id = tray_ids.show_id.clone();
    let exit_id = tray_ids.exit_id.clone();
    tray_icon::menu::MenuEvent::set_event_handler(Some(move |event: tray_icon::menu::MenuEvent| {
        if event.id() == &show_id {
            show_window_force();
        } else if event.id() == &exit_id {
            TRAY_EXIT_REQUESTED.store(true, Ordering::SeqCst);
            show_window_force(); // wake eframe so it can process the exit
        }
    }));

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
            theme::apply(&cc.egui_ctx);

            // Capture the HWND at startup.
            #[cfg(windows)]
            {
                use raw_window_handle::HasWindowHandle;
                if let Ok(handle) = cc.window_handle() {
                    if let raw_window_handle::RawWindowHandle::Win32(h) = handle.as_raw() {
                        STORED_HWND.store(
                            h.hwnd.get() as isize,
                            Ordering::SeqCst,
                        );
                    }
                }
            }

            let state: AppState = cc
                .storage
                .and_then(|s| eframe::get_value(s, eframe::APP_KEY))
                .unwrap_or_default();

            Ok(Box::new(OpenProtectApp {
                state,
                _tray_icon: tray_icon,
                icons: tray::IconSet::new(),
                last_poll: Instant::now() - Duration::from_secs(10),
                wants_exit: false,
            }))
        }),
    )
}

struct OpenProtectApp {
    state: AppState,
    _tray_icon: tray_icon::TrayIcon,
    icons: tray::IconSet,
    last_poll: Instant,
    wants_exit: bool,
}

impl eframe::App for OpenProtectApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.state);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Close button → hide to tray.
        if ctx.input(|i| i.viewport().close_requested()) && !self.wants_exit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            hide_window();
        }

        // Tray exit.
        if TRAY_EXIT_REQUESTED.swap(false, Ordering::SeqCst) {
            self.wants_exit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        // Poll VPN status every 3 seconds.
        if self.last_poll.elapsed() >= Duration::from_secs(3) {
            self.last_poll = Instant::now();
            let new_state = opc::poll_status();

            if matches!(new_state, opc::VpnState::Connected(_))
                && self.state.connect_time.is_none()
            {
                self.state.connect_time = Some(Instant::now());
            } else if matches!(new_state, opc::VpnState::Disconnected) {
                self.state.connect_time = None;
            }

            if self
                .state
                .connect_done
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                self.state.connect_in_flight = false;
            }

            if new_state != self.state.vpn_state {
                tray::update_state(&self._tray_icon, &self.icons, &new_state);
                self.state.vpn_state = new_state;
            }
        }

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
