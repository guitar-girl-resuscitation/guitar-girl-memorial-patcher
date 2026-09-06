use std::process::Command;
fn git(args: &[&str]) -> String {
    Command::new("git").args(args).output().ok().filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default().trim().to_owned()
}
fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads/main");
    println!("cargo:rustc-env=GGFM_SOURCE_COMMIT={}", git(&["rev-parse", "HEAD"]));
    println!("cargo:rustc-env=GGFM_SOURCE_UPDATED_AT={}", git(&["show", "-s", "--format=%cI", "HEAD"]));
}
