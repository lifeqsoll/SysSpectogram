//! Build BPF object with system clang (avoids rustc/bpf-linker LLVM mismatch on Arch).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let src = manifest_dir.join("ebpf/probes.c");
    let obj = out_dir.join("sysspectogram-ebpf");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=SYSSPECTOGRAM_SKIP_EBPF");

    if env::var_os("SYSSPECTOGRAM_SKIP_EBPF").is_some() {
        println!("cargo:warning=SYSSPECTOGRAM_SKIP_EBPF set — skipping BPF compile");
        // empty placeholder so include_bytes still works if feature off path
        let _ = std::fs::write(&obj, []);
        return;
    }

    let clang = which_clang();
    let status = Command::new(&clang)
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-Wall",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-c",
            src.to_str().unwrap(),
            "-o",
            obj.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=compiled BPF object {}", obj.display());
        }
        Ok(s) => {
            panic!("clang BPF compile failed: {s}. Install clang/libbpf. Or set SYSSPECTOGRAM_SKIP_EBPF=1");
        }
        Err(e) => {
            panic!("failed to run {clang}: {e}");
        }
    }
}

fn which_clang() -> String {
    env::var("CLANG").unwrap_or_else(|_| "clang".into())
}
