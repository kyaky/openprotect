//! Programmatically generated tray icons.
//!
//! Creates simple 32x32 colored circle icons. Replace with proper
//! PNG assets later for a polished look.

use tray_icon::Icon;

/// Create a 32x32 icon filled with the given RGBA color.
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
                // Filled circle
                rgba.extend_from_slice(&[r, g, b, 255]);
            } else if dist <= radius + 1.0 {
                // Anti-aliased edge
                let alpha = ((radius + 1.0 - dist) * 255.0) as u8;
                rgba.extend_from_slice(&[r, g, b, alpha]);
            } else {
                // Transparent
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    Icon::from_rgba(rgba, size, size).expect("failed to create icon")
}

pub fn connected() -> Icon {
    make_circle_icon(34, 197, 94) // green
}

pub fn disconnected() -> Icon {
    make_circle_icon(239, 68, 68) // red
}

pub fn connecting() -> Icon {
    make_circle_icon(234, 179, 8) // yellow
}
