//! Android release identity is fixed at build time, never at download/startup time.
use serde::Serialize;

const BASE_CODE: u32 = 800_000;
const MAX_REVISION: u32 = 2_100_000_000 - BASE_CODE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidVersion {
    pub revision: u32,
    pub version_code: u32,
    pub version_name: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VersionError {
    #[error(
        "unnumbered development build: set GGFM_BUILD_REVISION when compiling, or explicitly supply a positive development revision"
    )]
    Missing,
    #[error("revision exceeds Android's versionCode limit")]
    OutOfRange,
    #[error(
        "configured revision {configured} conflicts with compiled release {compiled}; remove versions.revision / --revision to use the release version"
    )]
    Conflict { configured: u32, compiled: u32 },
}

impl AndroidVersion {
    /// Zero means automatic. Numbered releases cannot be relabelled by old config.
    pub fn resolve(configured: u32) -> Result<Self, VersionError> {
        let compiled = env!("GGFM_COMPILED_REVISION")
            .parse()
            .expect("validated by build.rs");
        Self::resolve_with(configured, compiled)
    }

    fn resolve_with(configured: u32, compiled: u32) -> Result<Self, VersionError> {
        if compiled != 0 && configured != 0 && compiled != configured {
            return Err(VersionError::Conflict {
                configured,
                compiled,
            });
        }
        let revision = if compiled == 0 { configured } else { compiled };
        if revision == 0 {
            return Err(VersionError::Missing);
        }
        if revision > MAX_REVISION {
            return Err(VersionError::OutOfRange);
        }
        Ok(Self {
            revision,
            version_code: BASE_CODE + revision,
            version_name: format!("8.0.0-memorial.{revision}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_sequence_increases_android_code() {
        let first = AndroidVersion::resolve_with(0, 42).unwrap();
        let next = AndroidVersion::resolve_with(0, 43).unwrap();
        assert_eq!(first.version_code, 800042);
        assert_eq!(first.version_name, "8.0.0-memorial.42");
        assert!(next.version_code > first.version_code);
        assert!(first.version_code > 800001);
    }

    #[test]
    fn repeated_downloads_and_explicit_matching_revision_are_stable() {
        assert_eq!(
            AndroidVersion::resolve_with(0, 42),
            AndroidVersion::resolve_with(42, 42)
        );
        assert_eq!(
            AndroidVersion::resolve_with(0, 42),
            AndroidVersion::resolve_with(0, 42)
        );
    }

    #[test]
    fn stale_or_future_override_cannot_relabel_release() {
        for configured in [1, 41, 43, u32::MAX] {
            assert!(matches!(
                AndroidVersion::resolve_with(configured, 42),
                Err(VersionError::Conflict { .. })
            ));
        }
    }

    #[test]
    fn local_build_requires_explicit_version_and_checks_bounds() {
        assert_eq!(
            AndroidVersion::resolve_with(0, 0),
            Err(VersionError::Missing)
        );
        assert_eq!(
            AndroidVersion::resolve_with(MAX_REVISION, 0)
                .unwrap()
                .version_code,
            2_100_000_000
        );
        assert_eq!(
            AndroidVersion::resolve_with(MAX_REVISION + 1, 0),
            Err(VersionError::OutOfRange)
        );
        assert_eq!(
            AndroidVersion::resolve_with(u32::MAX, 0),
            Err(VersionError::OutOfRange)
        );
    }
}
