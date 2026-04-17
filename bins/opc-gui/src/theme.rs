//! Custom dark theme for OpenProtect — clean, modern VPN client look.

use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke, TextStyle, Visuals};

/// OpenProtect brand colours.
pub const ACCENT: Color32 = Color32::from_rgb(59, 130, 246); // blue-500
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(96, 165, 250); // blue-400
pub const GREEN: Color32 = Color32::from_rgb(34, 197, 94); // green-500
pub const YELLOW: Color32 = Color32::from_rgb(234, 179, 8); // yellow-500
pub const RED: Color32 = Color32::from_rgb(239, 68, 68); // red-500
pub const BG_PRIMARY: Color32 = Color32::from_rgb(15, 23, 42); // slate-900
pub const BG_SECONDARY: Color32 = Color32::from_rgb(30, 41, 59); // slate-800
pub const BG_SURFACE: Color32 = Color32::from_rgb(51, 65, 85); // slate-700
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(248, 250, 252); // slate-50
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(148, 163, 184); // slate-400
pub const TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139); // slate-500
pub const BORDER: Color32 = Color32::from_rgb(51, 65, 85); // slate-700

/// Apply the OpenProtect dark theme to egui.
pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.panel_fill = BG_PRIMARY;
    visuals.window_fill = BG_SECONDARY;
    visuals.extreme_bg_color = BG_PRIMARY;
    visuals.faint_bg_color = BG_SECONDARY;

    // Widget styling
    visuals.widgets.noninteractive.bg_fill = BG_SECONDARY;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_SECONDARY);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);

    visuals.widgets.inactive.bg_fill = BG_SURFACE;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);

    visuals.widgets.hovered.bg_fill = ACCENT;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);

    visuals.widgets.active.bg_fill = ACCENT_HOVER;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);

    // Selection
    visuals.selection.bg_fill = ACCENT.linear_multiply(0.3);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    // Window
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    ctx.set_visuals(visuals);

    // Font sizes
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(22.0)),
        (TextStyle::Body, FontId::proportional(14.0)),
        (TextStyle::Monospace, FontId::monospace(13.0)),
        (TextStyle::Button, FontId::proportional(14.0)),
        (TextStyle::Small, FontId::proportional(11.0)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style(style);
}
