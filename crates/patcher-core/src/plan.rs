use sha2::{Digest, Sha256};

use crate::{CompatibilityManifest, VerifiedPackage};

#[derive(Clone, Debug)]
pub struct ArtifactVersions {
    pub patch_commit: String,
    pub patch_version: String,
    pub server_version: String,
    pub server_sha256: String,
    pub server_abi: u32,
    pub signer_fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct PatchPlan {
    pub application_id: String,
    pub application_label: String,
    pub signer_fingerprint: String,
    pub cache_key: String,
    pub stages: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("compatibility manifest is not fail-closed")]
    NotFailClosed,
    #[error("patch commit is not a full 40-character Git object id")]
    UnpinnedPatch,
    #[error("server ABI {0} is unsupported")]
    UnsupportedServerAbi(u32),
    #[error("self-hosted application ID must extend the official memorial ID")]
    InvalidApplicationId,
}

impl PatchPlan {
    pub fn create(
        package: &VerifiedPackage,
        manifest: &CompatibilityManifest,
        artifacts: &ArtifactVersions,
        application_id: Option<&str>,
    ) -> Result<Self, PlanError> {
        if !manifest.fail_closed {
            return Err(PlanError::NotFailClosed);
        }
        if artifacts.patch_commit.len() != 40
            || !artifacts
                .patch_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PlanError::UnpinnedPatch);
        }
        if artifacts.server_abi != 1 {
            return Err(PlanError::UnsupportedServerAbi(artifacts.server_abi));
        }
        let application_id = application_id.unwrap_or(&manifest.output.application_id);
        if application_id != manifest.output.application_id
            && !application_id.starts_with(&(manifest.output.application_id.clone() + "."))
        {
            return Err(PlanError::InvalidApplicationId);
        }
        let tuple = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            package.outer_sha256,
            artifacts.patch_commit,
            artifacts.patch_version,
            artifacts.server_version,
            artifacts.server_sha256,
            artifacts.server_abi,
            application_id,
            artifacts.signer_fingerprint
        );
        let cache_key = hex::encode_upper(Sha256::digest(tuple.as_bytes()));
        Ok(Self {
            application_id: application_id.to_owned(),
            application_label: manifest.output.label.clone(),
            signer_fingerprint: artifacts.signer_fingerprint.clone(),
            cache_key,
            stages: vec![
                "verify-xapk-and-splits",
                "extract-request-workspace",
                "extract-master-sqlite-from-user-package",
                "inject-bootstrap-dex-native-hook-and-server",
                "apply-manifest-dex-il2cpp-and-policy-transforms",
                "rewrite-package-authorities-permissions-and-deep-links",
                "rebuild-all-splits",
                "zipalign-all-splits",
                "sign-all-splits-with-one-certificate",
                "rebuild-xapk-manifest",
                "verify-package-version-certificate-and-old-identifiers",
                "publish-for-explicit-device-smoke-test",
            ],
        })
    }
}
