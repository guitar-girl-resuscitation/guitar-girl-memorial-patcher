//! Optional, operator-owned original ARMv7 split for a universal ARM64 base.
//! No original bytes are part of this crate or its release artifacts.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSupplement {
    pub source_split: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub bootstrap_so: PathBuf,
    pub bootstrap_so_sha256: String,
    pub dobby_so: PathBuf,
    pub dobby_sha256: String,
    pub server_so: PathBuf,
    pub server_sha256: String,
}

impl NativeSupplement {
    pub(super) fn stage(&self, primary: &CompatibilityManifest, policy: &str,
            extracted: &Path, workspace: &Path) -> Result<CompatibilityManifest, PipelineError> {
        let profile = CompatibilityManifest::parse(&fs::read(&self.compatibility_manifest)?)
            .map_err(|e| PipelineError::PayloadMismatch(e.to_string()))?;
        if primary.source.abi != crate::manifest::AndroidAbi::Arm64
            || !profile.fail_closed || profile.schema != 1
            // Shared DEX/resource equivalence has been audited only for this
            // exact primary. New source versions need a fresh pairing audit.
            || !primary.source.xapk_sha256.eq_ignore_ascii_case("E395AD8A0BF09EA9425D7751388D61C31E9B63411640A716432AC97940BB9FAC")
            || profile.source.abi != crate::manifest::AndroidAbi::ArmV7
            || primary.source.version != profile.source.version
            || primary.source.global_metadata.sha256 != profile.source.global_metadata.sha256
            || primary.source.master_bundle.sha256 != profile.source.master_bundle.sha256 {
            return Err(PipelineError::PayloadMismatch("incompatible supplemental ABI/catalog".into()));
        }
        let abi = profile.source.abi;
        let split = profile.source.splits.iter().find(|s| s.name == abi.split_name())
            .ok_or_else(|| PipelineError::PayloadMismatch("missing supplemental split fingerprint".into()))?;
        let source_hash = sha256_file(&self.source_split)?;
        if !source_hash.eq_ignore_ascii_case(&split.sha256) {
            return Err(PipelineError::PayloadMismatch("supplemental original split SHA-256 mismatch".into()));
        }
        for (name, path, expected) in [("supplemental bootstrap", &self.bootstrap_so, &self.bootstrap_so_sha256),
                ("supplemental Dobby", &self.dobby_so, &self.dobby_sha256),
                ("supplemental Server", &self.server_so, &self.server_sha256)] {
            let actual = sha256_file(path)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(PipelineError::ArtifactHashMismatch { name, actual });
            }
            validate_elf_abi(path, abi)?;
        }
        validate_runtime_policy_fingerprints(&self.server_so, &self.bootstrap_so, policy)?;
        validate_native_artifact(&self.bootstrap_so, "libggfm_bootstrap.so", &["libdobby.so", "libggfm_server.so"])?;
        validate_native_artifact(&self.dobby_so, "libdobby.so", &[])?;
        validate_native_artifact(&self.server_so, "libggfm_server.so", &[])?;
        let destination = extracted.join(abi.split_name());
        if destination.exists() { return Err(PipelineError::OutputExists(destination)); }
        fs::copy(&self.source_split, &destination)?;
        if !sha256_file(&destination)?.eq_ignore_ascii_case(&split.sha256) {
            return Err(PipelineError::SourceChanged("supplemental split changed while copying".into()));
        }
        let validation = workspace.join("verify-armv7");
        fs::create_dir(&validation)?;
        verify_embedded_payloads(extracted, &profile, &validation)?;
        Ok(profile)
    }

    pub(super) fn inject(&self, rebuilt: &mut BTreeMap<String, PathBuf>, directory: &Path) -> Result<(), PipelineError> {
        let abi = crate::manifest::AndroidAbi::ArmV7;
        let original = rebuilt.get(abi.split_name())
            .ok_or_else(|| PipelineError::MissingXapkEntry(abi.split_name().into()))?;
        let output = directory.join("native-injected-armv7.apk");
        append_zip_entries(original, &output, &[
            (&self.bootstrap_so, abi.library("libggfm_bootstrap.so")),
            (&self.dobby_so, abi.library("libdobby.so")),
            (&self.server_so, abi.library("libggfm_server.so")),
        ])?;
        rebuilt.insert(abi.split_name().into(), output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supplement_rejects_wrong_catalog_architecture_and_source_before_injection() {
        let dir = tempfile::tempdir().unwrap();
        let v7 = dir.path().join("v7.json");
        fs::write(&v7, include_bytes!("../../../patch/compatibility/8.0.0-armv7.json")).unwrap();
        let source = dir.path().join("source.apk");
        fs::write(&source, b"not an original APK").unwrap();
        let extra = NativeSupplement { source_split: source, compatibility_manifest: v7,
            bootstrap_so: dir.path().join("absent"), bootstrap_so_sha256: "AB".repeat(32),
            dobby_so: dir.path().join("absent"), dobby_sha256: "AB".repeat(32),
            server_so: dir.path().join("absent"), server_sha256: "AB".repeat(32) };
        let mut primary = CompatibilityManifest::parse(include_bytes!("../../../patch/compatibility/8.0.0.json")).unwrap();
        let error = extra.stage(&primary, "", dir.path(), dir.path()).unwrap_err().to_string();
        assert!(error.contains("original split SHA-256 mismatch"));
        primary.source.global_metadata.sha256 = "AA".repeat(32);
        assert!(extra.stage(&primary, "", dir.path(), dir.path()).unwrap_err().to_string().contains("incompatible supplemental"));
        primary.source.abi = crate::manifest::AndroidAbi::ArmV7;
        assert!(extra.stage(&primary, "", dir.path(), dir.path()).is_err());
        assert!(!dir.path().join("config.armeabi_v7a.apk").exists());
    }
}
