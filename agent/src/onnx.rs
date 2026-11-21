//! Optional tract-onnx scorer. Scoring is a no-op unless the `onnx` feature
//! and a model (with a matching `.sha256` sidecar) are both present.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::types::AgentAlert;

#[cfg(feature = "onnx")]
type Plan = tract_onnx::prelude::TypedRunnableModel<tract_onnx::prelude::TypedModel>;

pub struct OnnxScorer {
    shadow: bool,
    #[cfg(feature = "onnx")]
    plan: Plan,
}

impl OnnxScorer {
    pub fn shadow(&self) -> bool {
        self.shadow
    }

    /// Load a model after its sha256 sidecar matches. Without the `onnx` feature this errors
    /// so the caller keeps the userspace rules unchanged.
    pub fn load(path: &Path, shadow: bool) -> Result<Self, String> {
        verify_sidecar_sha256(path)?;
        #[cfg(not(feature = "onnx"))]
        {
            let _ = shadow;
            Err(format!(
                "onnx feature not enabled (model {})",
                path.display()
            ))
        }
        #[cfg(feature = "onnx")]
        {
            let plan = load_plan(path)?;
            Ok(Self { shadow, plan })
        }
    }

    pub fn score_vector(&self, values: &[f32]) -> Result<f32, String> {
        #[cfg(not(feature = "onnx"))]
        {
            let _ = (self.shadow, values);
            Err("onnx feature not enabled".into())
        }
        #[cfg(feature = "onnx")]
        {
            score_with_plan(&self.plan, values)
        }
    }
}

/// Check `model.onnx.sha256` (or `model.sha256`) against the file bytes.
pub fn verify_sidecar_sha256(model: &Path) -> Result<(), String> {
    if !model.is_file() {
        return Err(format!("onnx model missing: {}", model.display()));
    }
    let sidecar = sidecar_path(model).ok_or_else(|| {
        format!("onnx sha256 sidecar missing for {}", model.display())
    })?;
    let text = fs::read_to_string(&sidecar).map_err(|err| format!("onnx sidecar: {err}"))?;
    let expect = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if expect.len() != 64 || !expect.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("onnx sidecar is not a sha256 hex digest: {}", sidecar.display()));
    }
    let bytes = fs::read(model).map_err(|err| format!("onnx model read: {err}"))?;
    let got = hex_encode(&Sha256::digest(&bytes));
    if got != expect {
        return Err(format!("onnx sha256 mismatch for {}", model.display()));
    }
    Ok(())
}

fn sidecar_path(model: &Path) -> Option<std::path::PathBuf> {
    let alongside = std::path::PathBuf::from(format!("{}.sha256", model.display()));
    if alongside.is_file() {
        return Some(alongside);
    }
    let swapped = model.with_extension("sha256");
    if swapped.is_file() {
        return Some(swapped);
    }
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

pub fn annotate(alert: &mut AgentAlert, scorer: Option<&OnnxScorer>) {
    let Some(scorer) = scorer else {
        return;
    };
    let score = match scorer.score_vector(&alert_features(alert)) {
        Ok(score) => score,
        Err(err) => {
            eprintln!("[sysspectogram-agent] onnx score: {err}");
            return;
        }
    };
    // Shadow and live both attach the score. Severity stays with RuleEngine.
    let mut map = match alert.extras.take() {
        Some(serde_json::Value::Object(existing)) => existing,
        _ => serde_json::Map::new(),
    };
    map.insert("ml_score".into(), serde_json::json!(score));
    map.insert("ml_shadow".into(), serde_json::json!(scorer.shadow()));
    alert.extras = Some(serde_json::Value::Object(map));
}

fn alert_features(alert: &AgentAlert) -> Vec<f32> {
    let sev = match alert.severity.as_str() {
        "info" => 0.1,
        "low" => 0.3,
        "medium" => 0.5,
        "high" => 0.75,
        "critical" => 1.0,
        _ => 0.5,
    };
    let pid = if alert.pid.is_some() { 1.0 } else { 0.0 };
    vec![sev, pid, (alert.message.len() as f32) / 256.0]
}

#[cfg(feature = "onnx")]
fn load_plan(path: &Path) -> Result<Plan, String> {
    use tract_onnx::prelude::*;
    tract_onnx::onnx()
        .model_for_path(path)
        .map_err(|err| format!("onnx load: {err}"))?
        .into_optimized()
        .map_err(|err| format!("onnx optimize: {err}"))?
        .into_runnable()
        .map_err(|err| format!("onnx runnable: {err}"))
}

#[cfg(feature = "onnx")]
fn score_with_plan(plan: &Plan, values: &[f32]) -> Result<f32, String> {
    use tract_onnx::prelude::*;
    let shape = plan
        .model()
        .input_fact(0)
        .map_err(|err| format!("onnx input: {err}"))?
        .shape
        .as_concrete()
        .map(|dims| dims.to_vec())
        .unwrap_or_else(|| vec![1, values.len().max(1)]);
    let n: usize = shape.iter().product();
    let mut buf = vec![0.0f32; n.max(1)];
    for (i, value) in values.iter().enumerate() {
        if i >= buf.len() {
            break;
        }
        buf[i] = *value;
    }
    let tensor = Tensor::from_shape(&shape, &buf).map_err(|err| format!("onnx tensor: {err}"))?;
    let outputs = plan
        .run(tvec!(tensor.into()))
        .map_err(|err| format!("onnx run: {err}"))?;
    let view = outputs
        .first()
        .ok_or_else(|| "onnx produced no output".to_string())?
        .to_array_view::<f32>()
        .map_err(|err| format!("onnx output: {err}"))?;
    Ok(view.iter().copied().next().unwrap_or(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sysspectogram-onnx-{name}-{}-{}",
            std::process::id(),
            name.len()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}.sha256", path.display()));
        path
    }

    #[test]
    fn sidecar_roundtrip() {
        let path = scratch("ok");
        fs::write(&path, b"model-bytes").unwrap();
        let digest = hex_encode(&Sha256::digest(b"model-bytes"));
        fs::write(format!("{}.sha256", path.display()), format!("{digest}  model\n")).unwrap();
        assert!(verify_sidecar_sha256(&path).is_ok());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}.sha256", path.display()));
    }

    #[test]
    fn sidecar_mismatch_and_missing() {
        let path = scratch("bad");
        fs::write(&path, b"model-bytes").unwrap();
        assert!(verify_sidecar_sha256(&path).is_err());
        fs::write(format!("{}.sha256", path.display()), format!("{}\n", "ab".repeat(32))).unwrap();
        assert!(verify_sidecar_sha256(&path).is_err());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}.sha256", path.display()));
    }

    #[test]
    fn load_without_model_is_err() {
        let missing = std::env::temp_dir().join(format!(
            "sysspectogram-onnx-missing-{}",
            std::process::id()
        ));
        match OnnxScorer::load(&missing, true) {
            Err(err) => assert!(err.contains("missing") || err.contains("not enabled")),
            Ok(_) => panic!("expected load to fail without a model"),
        }
    }
}
