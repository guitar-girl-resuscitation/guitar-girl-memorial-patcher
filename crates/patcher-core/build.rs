fn main() {
    println!("cargo:rerun-if-env-changed=GGFM_BUILD_REVISION");
    let revision = match std::env::var("GGFM_BUILD_REVISION") {
        Ok(value) => {
            let revision: u32 = value
                .parse()
                .expect("GGFM_BUILD_REVISION must be a positive integer");
            assert!(
                (1..=2_099_200_000).contains(&revision),
                "Android versionCode out of range"
            );
            revision
        }
        Err(std::env::VarError::NotPresent) => 0,
        Err(error) => panic!("invalid GGFM_BUILD_REVISION: {error}"),
    };
    println!("cargo:rustc-env=GGFM_COMPILED_REVISION={revision}");
}
