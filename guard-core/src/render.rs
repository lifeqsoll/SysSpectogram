//! Lightweight PNG panel via `plotters` (Rust-side charts without matplotlib).

use plotters::prelude::*;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Render a simple line chart of (ts, value) into PNG bytes.
pub fn render_metric_png(
    title: &str,
    points: &[(f64, f64)],
    width: u32,
    height: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let dir = std::env::temp_dir();
    let path: PathBuf = dir.join(format!(
        "sysspectogram-guard-core-{}.png",
        std::process::id()
    ));
    {
        let root = BitMapBackend::new(&path, (width, height)).into_drawing_area();
        root.fill(&RGBColor(15, 20, 25))?;
        if !points.is_empty() {
            let xs: Vec<f64> = points.iter().map(|p| p.0).collect();
            let ys: Vec<f64> = points.iter().map(|p| p.1).collect();
            let x_min = xs.iter().cloned().fold(f64::INFINITY, f64::min);
            let x_max = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let y_min = ys.iter().cloned().fold(f64::INFINITY, f64::min);
            let y_max = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let y_pad = ((y_max - y_min).abs() * 0.1).max(0.01);
            let mut chart = ChartBuilder::on(&root)
                .margin(12)
                .x_label_area_size(28)
                .y_label_area_size(40)
                .build_cartesian_2d(
                    x_min..x_max.max(x_min + 1.0),
                    (y_min - y_pad)..(y_max + y_pad),
                )?;
            let _ = title; // text labels need a font backend; series-only is enough for panels
            chart.draw_series(LineSeries::new(
                points.iter().copied(),
                RGBColor(59, 130, 246).stroke_width(2),
            ))?;
        }
        root.present()?;
    }
    let bytes = fs::read(&path)?;
    let _ = fs::remove_file(&path);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_non_empty_png() {
        let pts: Vec<(f64, f64)> = (0..20).map(|i| (i as f64, (i as f64).sin())).collect();
        let png = render_metric_png("cpu", &pts, 320, 180).expect("png");
        assert!(png.len() > 32);
        assert_eq!(&png[0..4], b"\x89PNG");
    }
}
