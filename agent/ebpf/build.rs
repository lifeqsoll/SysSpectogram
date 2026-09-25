fn main() {
    if let Ok(path) = which::which("bpf-linker") {
        println!("cargo:rerun-if-changed={}", path.display());
    } else {
        println!("cargo:warning=bpf-linker not found on PATH");
    }
}
