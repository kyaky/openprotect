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
    pub active_tab: Tab,
    #[serde(skip)]
    pub vpn_state: VpnState,
    #[serde(skip)]
    pub log_lines: Arc<Mutex<Vec<String>>>,
    #[serde(skip)]
    pub log_auto_scroll: bool,
    #[serde(skip)]
    pub connect_time: Option<std::time::Instant>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            portal: String::new(),
            username: String::new(),
            active_tab: Tab::Connect,
            vpn_state: VpnState::Disconnected,
            log_lines: Arc::new(Mutex::new(Vec::new())),
            log_auto_scroll: true,
            connect_time: None,
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
    // Clone the state enum to avoid borrow conflict.
    let vpn = state.vpn_state.clone();
    match vpn {
        VpnState::Connected(info) => connected_panel(ui, &info, state),
        VpnState::Connecting => connecting_panel(ui),
        VpnState::Disconnected => disconnected_panel(ui, state),
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

    ui.add_space(20.0);

    // Connect button
    let can_connect = !state.portal.trim().is_empty();
    ui.add_enabled_ui(can_connect, |ui| {
        let btn = egui::Button::new(
            RichText::new("Connect").size(15.0).strong().color(Color32::WHITE),
        )
        .fill(theme::ACCENT)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(ui.available_width(), 40.0));

        if ui.add(btn).clicked() {
            if let Ok(mut log) = state.log_lines.lock() {
                log.push(format!(
                    "[gui] connecting to {} ...",
                    state.portal.trim()
                ));
            }
            opc::connect(
                state.portal.trim(),
                state.username.trim(),
                state.log_lines.clone(),
            );
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

fn connecting_panel(ui: &mut egui::Ui) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.spinner();
        ui.add_space(12.0);
        ui.label(RichText::new("Connecting...").size(18.0).color(theme::YELLOW));
        ui.add_space(8.0);
        ui.label(
            RichText::new("Complete authentication in the browser or terminal if prompted.")
                .size(13.0)
                .color(theme::TEXT_SECONDARY),
        );
    });
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
        });
    });

    ui.add_space(8.0);

    // Log area
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
                ui.horizontal(|ui| {
                    ui.label(RichText::new("*").color(theme::ACCENT));
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
}
