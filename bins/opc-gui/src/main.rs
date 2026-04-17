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
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use views::AppState;

/// Shared flag: tray thread sets this to request window restore.
static TRAY_SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Shared flag: tray thread sets this to request app exit.
static TRAY_EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Whether the window is currently hidden to tray.
static WINDOW_HIDDEN: AtomicBool = AtomicBool::new(false);

fn main() -> eframe::Result<()> {
    // Build tray icon before eframe takes over the event loop.
    let icons = tray::IconSet::new();
    let (tray_icon, tray_ids) = tray::build(&icons);

    // Spawn a dedicated thread to poll tray events, because when
    // the window is hidden, eframe may not run update() frequently
    // enough (or at all) to catch tray menu clicks.
    let tray_ids_clone = Arc::new(tray_ids);
    let tray_ids_for_thread = tray_ids_clone.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(action) = tray::poll_menu(&tray_ids_for_thread) {
            match action {
                tray::TrayAction::Show => {
                    TRAY_SHOW_REQUESTED.store(true, Ordering::SeqCst);
                }
                tray::TrayAction::Exit => {
                    TRAY_EXIT_REQUESTED.store(true, Ordering::SeqCst);
                }
            }
        }
    });

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
                _tray_ids: tray_ids_clone,
                icons,
                last_poll: Instant::now() - Duration::from_secs(10),
                wants_exit: false,
            }))
        }),
    )
}

struct OpenProtectApp {
    state: AppState,
    tray_icon: tray_icon::TrayIcon,
    _tray_ids: Arc<tray::TrayMenuIds>,
    icons: tray::IconSet,
    last_poll: Instant,
    wants_exit: bool,
}

/// Hide the window using Win32 API (works even when egui event loop is idle).
#[cfg(windows)]
fn win32_hide_window() {
    unsafe {
        let hwnd = windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow();
        if !hwnd.is_null() {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
            );
        }
    }
}

/// Show and focus the window using Win32 API.
#[cfg(windows)]
fn win32_show_window(title: &str) {
    unsafe {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_title: Vec<u16> = OsStr::new(title)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(
            std::ptr::null(),
            wide_title.as_ptr(),
        );
        if !hwnd.is_null() {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW,
            );
            windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(windows))]
fn win32_hide_window() {}

#[cfg(not(windows))]
fn win32_show_window(_title: &str) {}

impl eframe::App for OpenProtectApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.state);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Intercept the window close button → hide to tray.
        if ctx.input(|i| i.viewport().close_requested()) && !self.wants_exit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            win32_hide_window();
            WINDOW_HIDDEN.store(true, Ordering::SeqCst);
        }

        // Check tray thread signals.
        if TRAY_EXIT_REQUESTED.swap(false, Ordering::SeqCst) {
            self.wants_exit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if TRAY_SHOW_REQUESTED.swap(false, Ordering::SeqCst) {
            win32_show_window("OpenProtect");
            WINDOW_HIDDEN.store(false, Ordering::SeqCst);
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
                tray::update_state(&self.tray_icon, &self.icons, &new_state);
                self.state.vpn_state = new_state;
            }
        }

        // Keep the event loop alive even when hidden.
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
