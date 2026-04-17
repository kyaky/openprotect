//! UI views for the OpenProtect GUI.

use eframe::egui::{self, Color32, CornerRadius, Layout, RichText, Stroke, Vec2};
use std::sync::{Arc, Mutex};

use crate::opc::{self, VpnState};
use crate::theme;

/// Which tab/page is active.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Tab {
    Connect,
    Logs,
    About,
}

/// Persistent app state.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppState {
    pub portal: String,
    pub username: String,
    /// Split tunnel routes (e.g. "10.0.0.0/8, 172.16.0.0/12").
    pub split_tunnel: String,
    #[serde(skip)]
    pub active_tab: Tab,
    #[serde(skip)]
    pub vpn_state: VpnState,
    #[serde(skip)]
    pub log_lines: Arc<Mutex<Vec<String>>>,
    #[serde(skip)]
    pub log_auto_scroll: bool,
    /// When true, pass `--log debug` to opc instead of `--log info`.
    pub verbose_log: bool,
    #[serde(skip)]
    pub connect_time: Option<std::time::Instant>,
    #[serde(skip)]
    pub connect_in_flight: bool,
    /// The SAML callback server URL detected from opc output (e.g. http://127.0.0.1:29999).
    /// Written by the connect thread, read by the UI.
    #[serde(skip)]
    pub saml_server_url_shared: Arc<Mutex<Option<String>>>,
    /// Cached copy of saml_server_url for the UI (avoids locking every frame).
    #[serde(skip)]
    pub saml_server_url: Option<String>,
    /// User-pasted globalprotectcallback: URL.
    #[serde(skip)]
    pub saml_paste_buf: String,
    /// Shared flag: set by the connect thread when it finishes.
    #[serde(skip)]
    pub connect_done: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            portal: String::new(),
            username: String::new(),
            split_tunnel: String::new(),
            active_tab: Tab::Connect,
            vpn_state: VpnState::Disconnected,
            log_lines: Arc::new(Mutex::new(Vec::new())),
            log_auto_scroll: true,
            verbose_log: false,
            connect_time: None,
            connect_in_flight: false,
            saml_server_url_shared: Arc::new(Mutex::new(None)),
            saml_server_url: None,
            saml_paste_buf: String::new(),
            connect_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl Default for VpnState {
    fn default() -> Self {
        VpnState::Disconnected
    }
}

/// Draw the sidebar navigation.
pub fn sidebar(ui: &mut egui::Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        ui.add_space(16.0);

        // Logo / Title
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("OPENPROTECT").size(18.0).strong().color(theme::ACCENT));
            ui.label(RichText::new("GlobalProtect VPN").size(10.0).color(theme::TEXT_MUTED));
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(12.0);

        // Status indicator
        let (dot_color, status_text) = match &state.vpn_state {
            VpnState::Connected(_) => (theme::GREEN, "Connected"),
            VpnState::Connecting => (theme::YELLOW, "Connecting"),
            VpnState::Disconnected => (theme::RED, "Disconnected"),
        };
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 5.0, dot_color);
            ui.label(RichText::new(status_text).size(12.0).color(theme::TEXT_SECONDARY));
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // Nav buttons
        nav_button(ui, "Connect", Tab::Connect, &mut state.active_tab);
        nav_button(ui, "Logs", Tab::Logs, &mut state.active_tab);
        nav_button(ui, "About", Tab::About, &mut state.active_tab);
    });
}

fn nav_button(ui: &mut egui::Ui, label: &str, tab: Tab, active: &mut Tab) {
    let is_active = *active == tab;
    let bg = if is_active {
        theme::ACCENT.linear_multiply(0.15)
    } else {
        Color32::TRANSPARENT
    };
    let fg = if is_active {
        theme::ACCENT
    } else {
        theme::TEXT_SECONDARY
    };

    let btn = egui::Button::new(RichText::new(label).color(fg).size(14.0))
        .fill(bg)
        .corner_radius(CornerRadius::same(6))
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(ui.available_width(), 32.0));

    if ui.add(btn).clicked() {
        *active = tab;
    }
}

/// Draw the Connect / Status view.
pub fn connect_view(ui: &mut egui::Ui, state: &mut AppState) {
    // Poll the shared SAML URL from the connect thread.
    if state.saml_server_url.is_none() {
        if let Ok(s) = state.saml_server_url_shared.lock() {
            if s.is_some() {
                state.saml_server_url = s.clone();
            }
        }
    }

    // Clone the state enum to avoid borrow conflict.
    let vpn = state.vpn_state.clone();
    match vpn {
        VpnState::Connected(info) => connected_panel(ui, &info, state),
        VpnState::Connecting => connecting_panel(ui, state),
        VpnState::Disconnected => {
            if state.connect_in_flight {
                connecting_panel(ui, state);
            } else {
                disconnected_panel(ui, state);
            }
        }
    }
}

fn disconnected_panel(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(20.0);
    ui.label(RichText::new("Connect to VPN").heading().color(theme::TEXT_PRIMARY));
    ui.add_space(16.0);

    // Portal input
    ui.label(RichText::new("Portal address").size(12.0).color(theme::TEXT_SECONDARY));
    ui.add_space(4.0);
    let portal_edit = egui::TextEdit::singleline(&mut state.portal)
        .hint_text("vpn.example.com")
        .desired_width(f32::INFINITY)
        .font(egui::FontId::proportional(14.0));
    ui.add(portal_edit);

    ui.add_space(12.0);

    // Username input
    ui.label(RichText::new("Username (optional)").size(12.0).color(theme::TEXT_SECONDARY));
    ui.add_space(4.0);
    let user_edit = egui::TextEdit::singleline(&mut state.username)
        .hint_text("user@example.com")
        .desired_width(f32::INFINITY)
        .font(egui::FontId::proportional(14.0));
    ui.add(user_edit);

    ui.add_space(12.0);

    // Split tunnel routes
    ui.label(
        RichText::new("Split tunnel routes (optional)")
            .size(12.0)
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(4.0);
    let split_edit = egui::TextEdit::singleline(&mut state.split_tunnel)
        .hint_text("10.0.0.0/8, 172.16.0.0/12")
        .desired_width(f32::INFINITY)
        .font(egui::FontId::proportional(14.0));
    ui.add(split_edit);
    ui.label(
        RichText::new("Comma-separated CIDRs. Only these subnets route through VPN.")
            .size(10.0)
            .color(theme::TEXT_MUTED),
    );

    ui.add_space(20.0);

    // Connect button — disabled while a connect is already in flight
    let can_connect = !state.portal.trim().is_empty() && !state.connect_in_flight;
    ui.add_enabled_ui(can_connect, |ui| {
        let label = if state.connect_in_flight {
            "Connecting..."
        } else {
            "Connect"
        };
        let btn = egui::Button::new(
            RichText::new(label).size(15.0).strong().color(Color32::WHITE),
        )
        .fill(theme::ACCENT)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(ui.available_width(), 40.0));

        if ui.add(btn).clicked() {
            state.connect_in_flight = true;
            state.connect_done.store(false, std::sync::atomic::Ordering::SeqCst);
            state.saml_server_url = None;
            state.saml_paste_buf.clear();
            if let Ok(mut log) = state.log_lines.lock() {
                log.push(format!(
                    "[gui] connecting to {} ...",
                    state.portal.trim()
                ));
            }
            opc::connect(
                state.portal.trim(),
                state.username.trim(),
                state.split_tunnel.trim(),
                state.verbose_log,
                state.log_lines.clone(),
                state.saml_server_url_shared.clone(),
                state.connect_done.clone(),
            );
            state.active_tab = Tab::Logs;
        }
    });

    ui.add_space(12.0);

    // Diagnose button
    if !state.portal.trim().is_empty() {
        let diag_btn = egui::Button::new(
            RichText::new("Diagnose").size(13.0).color(theme::TEXT_SECONDARY),
        )
        .fill(theme::BG_SURFACE)
        .corner_radius(CornerRadius::same(6))
        .min_size(Vec2::new(ui.available_width(), 32.0));

        if ui.add(diag_btn).clicked() {
            opc::diagnose(state.portal.trim(), state.log_lines.clone());
            state.active_tab = Tab::Logs;
        }
    }
}

fn connecting_panel(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        ui.spinner();
        ui.add_space(12.0);
        ui.label(RichText::new("Connecting...").size(18.0).color(theme::YELLOW));
    });

    // SAML paste panel — shown when the SAML HTTP server is detected.
    if let Some(server_url) = &state.saml_server_url.clone() {
        ui.add_space(16.0);
        egui::Frame::new()
            .fill(theme::BG_SECONDARY)
            .corner_radius(CornerRadius::same(8))
            .inner_margin(12.0)
            .stroke(Stroke::new(1.0, theme::YELLOW))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("SAML Authentication")
                        .size(14.0)
                        .strong()
                        .color(theme::YELLOW),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "1. Complete login in the browser\n\
                         2. On \"Authentication Complete\" page, right-click \
                         \"click here\" \u{2192} Copy Link\n\
                         3. Paste below (Ctrl+V)",
                    )
                    .size(12.0)
                    .color(theme::TEXT_SECONDARY),
                );
                ui.add_space(8.0);

                let edit = egui::TextEdit::singleline(&mut state.saml_paste_buf)
                    .hint_text("Paste globalprotectcallback: URL here...")
                    .desired_width(ui.available_width())
                    .font(egui::FontId::monospace(12.0));
                ui.add(edit);

                let has_callback = state
                    .saml_paste_buf
                    .trim()
                    .starts_with("globalprotectcallback:");

                if has_callback && state.saml_paste_buf.trim().len() > 30 {
                    // Auto-submit valid callback.
                    submit_saml(state, server_url);
                } else if has_callback {
                    ui.add_space(6.0);
                    let btn = egui::Button::new(
                        RichText::new("Submit Token")
                            .size(14.0)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(theme::GREEN)
                    .corner_radius(CornerRadius::same(6))
                    .min_size(Vec2::new(ui.available_width(), 34.0));

                    if ui.add(btn).clicked() {
                        submit_saml(state, server_url);
                    }
                }
            });
    } else {
        ui.add_space(8.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Complete authentication in the browser if prompted.")
                    .size(13.0)
                    .color(theme::TEXT_SECONDARY),
            );
        });
    }
}

fn connected_panel(ui: &mut egui::Ui, info: &opc::StatusInfo, state: &mut AppState) {
    ui.add_space(20.0);

    // Header
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 7.0, theme::GREEN);
        ui.label(RichText::new("Connected").size(20.0).strong().color(theme::GREEN));
    });

    ui.add_space(16.0);

    // Details card
    egui::Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(16.0)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            detail_row(ui, "Portal", &info.portal);
            detail_row(ui, "Gateway", &info.gateway);
            detail_row(
                ui,
                "IP Address",
                info.local_ipv4.as_deref().unwrap_or("--"),
            );
            detail_row(ui, "User", &info.user);
            if let Some(iface) = &info.tun_ifname {
                detail_row(ui, "Interface", iface);
            }
            detail_row(ui, "Uptime", &format_uptime(info.uptime_seconds));

            // Split tunnel status
            if state.split_tunnel.trim().is_empty() {
                detail_row(ui, "Mode", "Full tunnel (all traffic)");
            } else {
                detail_row(ui, "Mode", "Split tunnel");
                detail_row(ui, "Routes", state.split_tunnel.trim());
            }
        });

    ui.add_space(20.0);

    // Disconnect button
    let btn = egui::Button::new(
        RichText::new("Disconnect").size(15.0).strong().color(Color32::WHITE),
    )
    .fill(theme::RED)
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(ui.available_width(), 40.0));

    if ui.add(btn).clicked() {
        opc::disconnect();
        state.connect_time = None;
        if let Ok(mut log) = state.log_lines.lock() {
            log.push("[gui] disconnect requested".to_string());
        }
    }
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{label}:"))
                .size(13.0)
                .color(theme::TEXT_MUTED),
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).size(13.0).strong().color(theme::TEXT_PRIMARY));
        });
    });
}

/// Maximum log lines kept in memory.
const MAX_LOG_LINES: usize = 5000;

fn submit_saml(state: &mut AppState, server_url: &str) {
    opc::post_saml_callback(server_url, state.saml_paste_buf.trim(), state.log_lines.clone());
    if let Ok(mut l) = state.log_lines.lock() {
        l.push("[gui] SAML callback submitted".to_string());
    }
    state.saml_paste_buf.clear();
    state.saml_server_url = None;
    if let Ok(mut s) = state.saml_server_url_shared.lock() {
        *s = None;
    }
    state.connect_in_flight = false;
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else {
        format!("{m}m {s:02}s")
    }
}

/// Draw the log viewer.
pub fn log_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Logs").heading().color(theme::TEXT_PRIMARY));
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button(RichText::new("Clear").size(12.0).color(theme::TEXT_SECONDARY))
                .clicked()
            {
                if let Ok(mut log) = state.log_lines.lock() {
                    log.clear();
                }
            }
            ui.checkbox(&mut state.log_auto_scroll, "Auto-scroll");
            ui.checkbox(&mut state.verbose_log, "Verbose");
        });
    });

    ui.add_space(8.0);

    // Log area — trim to max size.
    if let Ok(mut l) = state.log_lines.lock() {
        if l.len() > MAX_LOG_LINES {
            let drain = l.len() - MAX_LOG_LINES;
            l.drain(..drain);
        }
    }
    let lines: Vec<String> = state
        .log_lines
        .lock()
        .map(|l| l.clone())
        .unwrap_or_default();

    egui::Frame::new()
        .fill(Color32::from_rgb(10, 15, 30))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(8.0)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(ui.available_height())
                .stick_to_bottom(state.log_auto_scroll)
                .show(ui, |ui| {
                    for line in &lines {
                        let color = if line.starts_with("[error]") {
                            theme::RED
                        } else if line.starts_with("[warn]") {
                            theme::YELLOW
                        } else if line.starts_with("[gui]") || line.starts_with("[diagnose]") {
                            theme::ACCENT
                        } else {
                            theme::TEXT_SECONDARY
                        };
                        ui.label(RichText::new(line).monospace().size(12.0).color(color));
                    }
                    if lines.is_empty() {
                        ui.label(
                            RichText::new("No log entries yet.")
                                .size(12.0)
                                .color(theme::TEXT_MUTED),
                        );
                    }
                });
        });
}

/// Draw the About page.
pub fn about_view(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().show(ui, |ui| {
    ui.set_max_width(ui.available_width());
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new("OPENPROTECT").size(28.0).strong().color(theme::ACCENT));
        ui.add_space(4.0);
        ui.label(
            RichText::new("Open-source GlobalProtect VPN client")
                .size(14.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                .size(12.0)
                .color(theme::TEXT_MUTED),
        );
    });

    ui.add_space(24.0);

    egui::Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(16.0)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.label(RichText::new("Features").size(15.0).strong().color(theme::TEXT_PRIMARY));
            ui.add_space(8.0);

            let features = [
                "Full GlobalProtect protocol support",
                "SAML / Okta headless authentication",
                "Windows NRPT split-tunnel DNS",
                "HIP report submission",
                "Multi-portal & gateway latency selection",
                "Auto-reconnect with cookie re-auth",
                "Prometheus metrics endpoint",
                "Cross-platform (Windows, Linux, macOS)",
            ];

            for feat in features {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("\u{2022}").color(theme::ACCENT));
                    ui.label(RichText::new(feat).size(13.0).color(theme::TEXT_SECONDARY));
                });
            }
        });

    ui.add_space(16.0);

    egui::Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(16.0)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.label(RichText::new("Links").size(15.0).strong().color(theme::TEXT_PRIMARY));
            ui.add_space(8.0);

            if ui
                .add(egui::Label::new(
                    RichText::new("GitHub Repository")
                        .size(13.0)
                        .color(theme::ACCENT)
                        .underline(),
                ).sense(egui::Sense::click()))
                .clicked()
            {
                let _ = open::that("https://github.com/kyaky/openprotect");
            }

            ui.add_space(4.0);

            if ui
                .add(egui::Label::new(
                    RichText::new("Report an Issue")
                        .size(13.0)
                        .color(theme::ACCENT)
                        .underline(),
                ).sense(egui::Sense::click()))
                .clicked()
            {
                let _ = open::that("https://github.com/kyaky/openprotect/issues");
            }
        });

    ui.add_space(16.0);

    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new("Licensed under Apache-2.0 OR MIT")
                .size(11.0)
                .color(theme::TEXT_MUTED),
        );
    });
    }); // ScrollArea
}
