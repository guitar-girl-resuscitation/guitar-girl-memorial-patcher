use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read},
    path::{Component, Path},
};

use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::CompatibilityManifest;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_xapk_bytes: u64,
    pub max_entries: usize,
    pub max_expanded_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_work_bytes: u64,
    pub tool_timeout_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_xapk_bytes: 768 * 1024 * 1024,
            max_entries: 64,
            max_expanded_bytes: 1536 * 1024 * 1024,
            max_entry_bytes: 768 * 1024 * 1024,
            max_work_bytes: 6 * 1024 * 1024 * 1024,
            tool_timeout_seconds: 15 * 60,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedPackage {
    pub outer_sha256: String,
    pub source_version: String,
    pub splits: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid ZIP/XAPK: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("source is too large: {0} bytes")]
    SourceTooLarge(u64),
    #[error("unsupported source SHA-256 {actual}")]
    Unsupported { actual: String },
    #[error("archive has too many entries: {0}")]
    TooManyEntries(usize),
    #[error("unsafe archive entry {0}")]
    UnsafeEntry(String),
    #[error("entry {name} is too large: {size} bytes")]
    EntryTooLarge { name: String, size: u64 },
    #[error("expanded archive is too large: {0} bytes")]
    ExpandedTooLarge(u64),
    #[error("required split is missing: {0}")]
    MissingSplit(String),
    #[error("split {name} hash mismatch: {actual}")]
    SplitMismatch { name: String, actual: String },
    #[error("unexpected APK split {0}")]
    UnexpectedSplit(String),
}

pub fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode_upper(digest.finalize()))
}

pub fn verify_xapk(
    path: &Path,
    manifest: &CompatibilityManifest,
    limits: Limits,
) -> Result<VerifiedPackage, VerifyError> {
    let size = path.metadata()?.len();
    if size > limits.max_xapk_bytes {
        return Err(VerifyError::SourceTooLarge(size));
    }
    let outer_sha256 = sha256_file(path)?;
    if !outer_sha256.eq_ignore_ascii_case(&manifest.source.xapk_sha256) {
        return Err(VerifyError::Unsupported {
            actual: outer_sha256,
        });
    }
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > limits.max_entries {
        return Err(VerifyError::TooManyEntries(archive.len()));
    }
    let expected: BTreeMap<_, _> = manifest
        .source
        .splits
        .iter()
        .map(|split| (split.name.as_str(), split.sha256.as_str()))
        .collect();
    let mut found = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        if !is_safe_relative(&name) || !names.insert(name.clone()) {
            return Err(VerifyError::UnsafeEntry(name));
        }
        if entry.size() > limits.max_entry_bytes {
            return Err(VerifyError::EntryTooLarge {
                name,
                size: entry.size(),
            });
        }
        expanded = expanded.saturating_add(entry.size());
        if expanded > limits.max_expanded_bytes {
            return Err(VerifyError::ExpandedTooLarge(expanded));
        }
        if name.ends_with(".apk") {
            let Some(expected_hash) = expected.get(name.as_str()) else {
                return Err(VerifyError::UnexpectedSplit(name));
            };
            let mut digest = Sha256::new();
            io::copy(&mut entry, &mut digest)?;
            let actual = hex::encode_upper(digest.finalize());
            if !actual.eq_ignore_ascii_case(expected_hash) {
                return Err(VerifyError::SplitMismatch { name, actual });
            }
            found.insert(name, actual);
        }
    }
    for required in expected.keys() {
        if !found.contains_key(*required) {
            return Err(VerifyError::MissingSplit((*required).to_owned()));
        }
    }
    Ok(VerifiedPackage {
        outer_sha256,
        source_version: manifest.source.version.clone(),
        splits: found,
    })
}

fn is_safe_relative(name: &str) -> bool {
    // ZIP entry names are platform-independent. A Windows drive or separator
    // must not become a harmless-looking normal component on a Linux worker.
    if name.contains(':') || name.contains('\\') {
        return false;
    }
    let path = Path::new(name);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        assert!(!is_safe_relative("../base.apk"));
        assert!(!is_safe_relative("/base.apk"));
        assert!(!is_safe_relative("C:/base.apk"));
        assert!(is_safe_relative("base.apk"));
    }
}
