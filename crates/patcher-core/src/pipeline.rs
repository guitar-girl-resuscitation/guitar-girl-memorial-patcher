use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{CompatibilityManifest, Limits, PatchPlan, VerifiedPackage, sha256_file, verify_xapk};

#[derive(Clone, Debug)]
pub struct Toolchain {
    pub java: PathBuf,
    pub apktool_jar: PathBuf,
    pub python: PathBuf,
    pub aapt2: PathBuf,
    pub zipalign: PathBuf,
    pub apksigner: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PatchArtifacts {
    pub patch_root: PathBuf,
    pub bootstrap_dex: PathBuf,
    pub bootstrap_dex_sha256: String,
    pub bootstrap_so: PathBuf,
    pub bootstrap_so_sha256: String,
    pub dobby_so: PathBuf,
    pub dobby_sha256: String,
    pub server_so: PathBuf,
    pub server_sha256: String,
    pub policy_manifest: PathBuf,
    pub policy_sha256: String,
}

#[derive(Clone, Debug)]
pub struct SigningConfig {
    pub keystore: PathBuf,
    pub alias: String,
    pub store_password_env: String,
    pub key_password_env: Option<String>,
}

pub struct Pipeline {
    pub tools: Toolchain,
    pub artifacts: PatchArtifacts,
    pub signing: SigningConfig,
    pub work_root: PathBuf,
    pub limits: Limits,
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("source verification failed: {0}")]
    Verify(#[from] crate::VerifyError),
    #[error("required artifact does not exist: {0}")]
    MissingArtifact(PathBuf),
    #[error("server artifact hash mismatch: {0}")]
    ServerHashMismatch(String),
    #[error("server does not embed the selected policy SHA-256: {0}")]
    ServerPolicyMismatch(String),
    #[error("{name} artifact hash mismatch: {actual}")]
    ArtifactHashMismatch { name: &'static str, actual: String },
    #[error("verified source changed before patching: {0}")]
    SourceChanged(String),
    #[error("embedded source payload mismatch: {0}")]
    PayloadMismatch(String),
    #[error("external tool failed: {program} ({status})")]
    Tool { program: String, status: i32 },
    #[error("external tool timed out after {seconds} seconds: {program}")]
    ToolTimeout { program: String, seconds: u64 },
    #[error("patch workspace exceeded its {limit} byte disk quota: {actual} bytes")]
    WorkQuota { actual: u64, limit: u64 },
    #[error("XAPK manifest is missing {0}")]
    MissingXapkEntry(String),
    #[error("base APK could not be identified")]
    MissingBase,
    #[error("output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("output validation failed: {0}")]
    OutputValidation(String),
}

impl Pipeline {
    pub fn run(
        &self,
        source: &Path,
        manifest: &CompatibilityManifest,
        verified: &VerifiedPackage,
        plan: &PatchPlan,
        output: &Path,
        memorial_revision: u32,
    ) -> Result<(), PipelineError> {
        if output.exists() {
            return Err(PipelineError::OutputExists(output.to_owned()));
        }
        self.validate_artifacts()?;
        let current = verify_xapk(source, manifest, self.limits)?;
        if current.outer_sha256 != verified.outer_sha256 {
            return Err(PipelineError::SourceChanged(current.outer_sha256));
        }
        fs::create_dir_all(&self.work_root)?;
        let workspace = tempfile::Builder::new()
            .prefix("ggfm-request-")
            .tempdir_in(&self.work_root)?;
        let extracted = workspace.path().join("xapk");
        fs::create_dir(&extracted)?;
        extract_xapk(source, &extracted)?;
        enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;
        verify_embedded_payloads(&extracted, manifest, workspace.path())?;

        let base_name = manifest
            .source
            .splits
            .iter()
            .map(|split| split.name.as_str())
            .find(|name| *name != "config.arm64_v8a.apk" && *name != "base_assets.apk")
            .ok_or(PipelineError::MissingBase)?;
        let version_code = 800_000_i64 + i64::from(memorial_revision);
        let version_name = format!("8.0.0-memorial.{memorial_revision}");
        let unsigned_dir = workspace.path().join("unsigned");
        let signed_dir = workspace.path().join("signed");
        let framework_dir = workspace.path().join("apktool-framework");
        fs::create_dir(&unsigned_dir)?;
        fs::create_dir(&signed_dir)?;
        fs::create_dir(&framework_dir)?;

        let mut rebuilt = BTreeMap::new();
        for split in &manifest.source.splits {
            let decoded = workspace.path().join("decoded").join(&split.name);
            run_checked(
                &self.tools.java,
                &[
                    "-jar".into(),
                    self.tools.apktool_jar.as_os_str().into(),
                    "d".into(),
                    "-f".into(),
                    "-j".into(),
                    "2".into(),
                    "-s".into(),
                    "-p".into(),
                    framework_dir.as_os_str().into(),
                    extracted.join(&split.name).as_os_str().into(),
                    "-o".into(),
                    decoded.as_os_str().into(),
                ],
                self.tool_timeout(),
            )?;
            let decoded_manifest = decoded.join("AndroidManifest.xml");
            let mut transform_args = vec![
                self.artifacts
                    .patch_root
                    .join("tools/transform_manifest.py")
                    .into_os_string(),
                decoded_manifest.clone().into_os_string(),
                decoded_manifest.clone().into_os_string(),
                "--old-package".into(),
                "com.neowiz.game.guitargirl".into(),
                "--new-package".into(),
                plan.application_id.clone().into(),
                "--label".into(),
                plan.application_label.clone().into(),
                "--version-code".into(),
                version_code.to_string().into(),
                "--version-name".into(),
                version_name.clone().into(),
            ];
            if split.name == base_name {
                transform_args.push("--base".into());
            }
            run_checked(&self.tools.python, &transform_args, self.tool_timeout())?;
            validate_transformed_manifest(
                &decoded_manifest,
                &plan.application_id,
                "com.neowiz.game.guitargirl",
                version_code,
                &version_name,
                split.name == base_name,
                &plan.application_label,
            )?;
            let unsigned = unsigned_dir.join(&split.name);
            if split.name == base_name {
                run_checked(
                    &self.tools.java,
                    &[
                        "-jar".into(),
                        self.tools.apktool_jar.as_os_str().into(),
                        "b".into(),
                        "-j".into(),
                        "2".into(),
                        "-p".into(),
                        framework_dir.as_os_str().into(),
                        decoded.as_os_str().into(),
                        "-o".into(),
                        unsigned.as_os_str().into(),
                    ],
                    self.tool_timeout(),
                )?;
            } else {
                // Apktool 3 does not pass a framework table to aapt2 when a
                // split contains only a manifest. Compile that manifest with
                // aapt2 directly, then replace only AndroidManifest.xml in the
                // original split so native/assets payloads remain byte-exact.
                let manifest_apk = unsigned_dir.join(format!("{}.manifest.apk", split.name));
                run_checked(
                    &self.tools.aapt2,
                    &[
                        "link".into(),
                        "-o".into(),
                        manifest_apk.as_os_str().into(),
                        "--manifest".into(),
                        decoded_manifest.as_os_str().into(),
                        "-I".into(),
                        framework_dir.join("1.apk").as_os_str().into(),
                    ],
                    self.tool_timeout(),
                )?;
                let compiled_manifest =
                    unsigned_dir.join(format!("{}.AndroidManifest.xml", split.name));
                extract_zip_member(&manifest_apk, "AndroidManifest.xml", &compiled_manifest)?;
                append_zip_entries(
                    &extracted.join(&split.name),
                    &unsigned,
                    &[(&compiled_manifest, "AndroidManifest.xml".to_owned())],
                )?;
            }
            rebuilt.insert(split.name.clone(), unsigned);
            enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;
        }

        let master = workspace.path().join("master.sqlite");
        let table_bundle = workspace.path().join("table_db.ab");
        let transformed_table_bundle = workspace.path().join("table_db.memorial.ab");
        let master_transform_report = workspace.path().join("master-transform-report.json");
        extract_zip_member(
            &extracted.join("base_assets.apk"),
            "assets/AssetBundles/Android/table/table_db.ab",
            &table_bundle,
        )?;
        run_checked(
            &self.tools.python,
            &[
                self.artifacts
                    .patch_root
                    .join("tools/extract_master_sqlite.py")
                    .into_os_string(),
                table_bundle.clone().into_os_string(),
                master.clone().into_os_string(),
            ],
            self.tool_timeout(),
        )?;
        run_checked(
            &self.tools.python,
            &[
                self.artifacts
                    .patch_root
                    .join("tools/transform_master_bundle.py")
                    .into_os_string(),
                table_bundle.clone().into_os_string(),
                transformed_table_bundle.clone().into_os_string(),
                self.artifacts.policy_manifest.clone().into_os_string(),
                "--expected-sha256".into(),
                manifest.source.master_bundle.sha256.clone().into(),
                "--report".into(),
                master_transform_report.clone().into_os_string(),
            ],
            self.tool_timeout(),
        )?;
        let transformed_table_bundle_sha256 = sha256_file(&transformed_table_bundle)?;
        let bundle_metadata = workspace.path().join("bundle-metadata");
        run_checked(
            &self.tools.python,
            &[
                self.artifacts
                    .patch_root
                    .join("tools/transform_bundle_metadata.py")
                    .into_os_string(),
                extracted.join("base_assets.apk").into_os_string(),
                transformed_table_bundle.clone().into_os_string(),
                bundle_metadata.clone().into_os_string(),
            ],
            self.tool_timeout(),
        )?;
        enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;

        let assets = rebuilt
            .get("base_assets.apk")
            .ok_or_else(|| PipelineError::MissingXapkEntry("base_assets.apk".into()))?
            .clone();
        let patched_assets = unsigned_dir.join("base-assets-policy.apk");
        let metadata_names = [
            "Android",
            "Android.manifest",
            "table/table_db.ab.manifest",
            "table/table_bundlesize.ab",
            "table/table_bundlesize.ab.manifest",
        ];
        let metadata_paths: Vec<PathBuf> = metadata_names
            .iter()
            .map(|name| bundle_metadata.join(name))
            .collect();
        let mut assets_to_replace = vec![(
            &transformed_table_bundle,
            "assets/AssetBundles/Android/table/table_db.ab".to_owned(),
        )];
        assets_to_replace.extend(
            metadata_paths
                .iter()
                .zip(metadata_names.iter())
                .map(|(path, name)| (path, format!("assets/AssetBundles/Android/{name}"))),
        );
        append_zip_entries(&assets, &patched_assets, &assets_to_replace)?;
        rebuilt.insert("base_assets.apk".into(), patched_assets);

        let base = rebuilt
            .get(base_name)
            .ok_or(PipelineError::MissingBase)?
            .clone();
        let bootstrap_dex_name = next_dex_name(&base)?;
        let patched_base = unsigned_dir.join("base-injected.apk");
        append_zip_entries(
            &base,
            &patched_base,
            &[
                (&self.artifacts.bootstrap_dex, bootstrap_dex_name.clone()),
                (
                    &self.artifacts.policy_manifest,
                    "assets/ggfm/policy.json".to_owned(),
                ),
                (&master, "assets/ggfm/master.sqlite".to_owned()),
                (
                    &master_transform_report,
                    "assets/ggfm/master-transform-report.json".to_owned(),
                ),
            ],
        )?;
        rebuilt.insert(base_name.to_owned(), patched_base);

        let arm = rebuilt
            .get("config.arm64_v8a.apk")
            .ok_or_else(|| PipelineError::MissingXapkEntry("config.arm64_v8a.apk".into()))?;
        let patched_arm = unsigned_dir.join("arm64-injected.apk");
        append_zip_entries(
            arm,
            &patched_arm,
            &[
                (
                    &self.artifacts.bootstrap_so,
                    "lib/arm64-v8a/libggfm_bootstrap.so".into(),
                ),
                (&self.artifacts.dobby_so, "lib/arm64-v8a/libdobby.so".into()),
                (
                    &self.artifacts.server_so,
                    "lib/arm64-v8a/libggfm_server.so".into(),
                ),
            ],
        )?;
        rebuilt.insert("config.arm64_v8a.apk".into(), patched_arm);
        enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;

        for (name, unsigned) in &rebuilt {
            let aligned = signed_dir.join(format!("{name}.aligned"));
            run_checked(
                &self.tools.zipalign,
                &[
                    "-p".into(),
                    "-f".into(),
                    "4".into(),
                    unsigned.as_os_str().into(),
                    aligned.as_os_str().into(),
                ],
                self.tool_timeout(),
            )?;
            let signed = signed_dir.join(name);
            let mut arguments = vec![
                "sign".into(),
                "--ks".into(),
                self.signing.keystore.as_os_str().into(),
                "--ks-key-alias".into(),
                self.signing.alias.clone().into(),
                "--ks-pass".into(),
                format!("env:{}", self.signing.store_password_env).into(),
                "--out".into(),
                signed.as_os_str().into(),
            ];
            if let Some(variable) = &self.signing.key_password_env {
                arguments.extend(["--key-pass".into(), format!("env:{variable}").into()]);
            }
            arguments.push(aligned.as_os_str().into());
            run_checked(&self.tools.apksigner, &arguments, self.tool_timeout())?;
            run_checked(
                &self.tools.apksigner,
                &[
                    "verify".into(),
                    "--verbose".into(),
                    "--print-certs".into(),
                    signed.as_os_str().into(),
                ],
                self.tool_timeout(),
            )?;
            let actual_fingerprint =
                apk_signer_fingerprint(&self.tools.apksigner, &signed, self.tool_timeout())?;
            if normalize_fingerprint(&actual_fingerprint)
                != normalize_fingerprint(&plan.signer_fingerprint)
            {
                return Err(PipelineError::OutputValidation(format!(
                    "split {name} signer SHA-256 is {actual_fingerprint}, expected {}",
                    plan.signer_fingerprint
                )));
            }
            validate_signed_manifest(
                &self.tools.aapt2,
                &signed,
                SignedManifestExpectation {
                    application_id: &plan.application_id,
                    retired_application_id: "com.neowiz.game.guitargirl",
                    version_code,
                    version_name: &version_name,
                    base: name == base_name,
                    label: &plan.application_label,
                },
                self.tool_timeout(),
            )?;
            enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;
        }

        validate_injected_payloads(
            &signed_dir,
            base_name,
            &bootstrap_dex_name,
            &transformed_table_bundle_sha256,
        )?;

        let staged_output = workspace.path().join("validated-output.xapk");
        build_xapk(
            &extracted,
            &signed_dir,
            manifest,
            plan,
            version_code,
            &version_name,
            &staged_output,
        )?;
        validate_output_xapk(
            &staged_output,
            manifest,
            plan,
            version_code,
            &version_name,
            base_name,
        )?;
        enforce_work_quota(workspace.path(), self.limits.max_work_bytes)?;
        publish_noclobber(&staged_output, output)?;
        let _keep_alive_until_success: &TempDir = &workspace;
        Ok(())
    }

    fn tool_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.tool_timeout_seconds)
    }

    pub fn validate_artifacts(&self) -> Result<(), PipelineError> {
        for path in [
            &self.tools.java,
            &self.tools.apktool_jar,
            &self.tools.python,
            &self.tools.aapt2,
            &self.tools.zipalign,
            &self.tools.apksigner,
            &self.artifacts.patch_root,
            &self.artifacts.bootstrap_dex,
            &self.artifacts.bootstrap_so,
            &self.artifacts.dobby_so,
            &self.artifacts.server_so,
            &self.artifacts.policy_manifest,
            &self.signing.keystore,
        ] {
            if !path.exists() {
                return Err(PipelineError::MissingArtifact(path.clone()));
            }
        }
        let actual = sha256_file(&self.artifacts.server_so)?;
        if !actual.eq_ignore_ascii_case(&self.artifacts.server_sha256) {
            return Err(PipelineError::ServerHashMismatch(actual));
        }
        for (name, path, expected) in [
            (
                "bootstrap DEX",
                &self.artifacts.bootstrap_dex,
                &self.artifacts.bootstrap_dex_sha256,
            ),
            (
                "bootstrap native library",
                &self.artifacts.bootstrap_so,
                &self.artifacts.bootstrap_so_sha256,
            ),
            (
                "Dobby",
                &self.artifacts.dobby_so,
                &self.artifacts.dobby_sha256,
            ),
            (
                "policy manifest",
                &self.artifacts.policy_manifest,
                &self.artifacts.policy_sha256,
            ),
        ] {
            let actual = sha256_file(path)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(PipelineError::ArtifactHashMismatch { name, actual });
            }
        }
        validate_runtime_policy_fingerprints(
            &self.artifacts.server_so,
            &self.artifacts.bootstrap_so,
            &self.artifacts.policy_sha256,
        )?;
        validate_native_artifact(
            &self.artifacts.bootstrap_so,
            "libggfm_bootstrap.so",
            &["libdobby.so", "libggfm_server.so"],
        )?;
        validate_native_artifact(&self.artifacts.dobby_so, "libdobby.so", &[])?;
        validate_native_artifact(&self.artifacts.server_so, "libggfm_server.so", &[])?;
        Ok(())
    }
}

fn validate_runtime_policy_fingerprints(
    server: &Path,
    bootstrap: &Path,
    expected_policy_sha256: &str,
) -> Result<(), PipelineError> {
    validate_server_policy_fingerprint(server, expected_policy_sha256)?;
    validate_server_policy_fingerprint(bootstrap, expected_policy_sha256).map_err(|error| {
        match error {
            PipelineError::ServerPolicyMismatch(expected) => PipelineError::OutputValidation(
                format!("bootstrap policy fingerprint mismatch: expected {expected}; rebuild native Patch"),
            ),
            other => other,
        }
    })
}

fn validate_server_policy_fingerprint(
    server: &Path,
    expected_policy_sha256: &str,
) -> Result<(), PipelineError> {
    if expected_policy_sha256.len() != 64
        || !expected_policy_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PipelineError::ServerPolicyMismatch(
            expected_policy_sha256.to_owned(),
        ));
    }
    let expected = expected_policy_sha256.to_ascii_uppercase();
    let bytes = fs::read(server)?;
    if !bytes
        .windows(expected.len())
        .any(|window| window == expected.as_bytes())
    {
        return Err(PipelineError::ServerPolicyMismatch(expected));
    }
    Ok(())
}

#[derive(Debug)]
struct ElfDynamic {
    needed: Vec<String>,
    soname: Option<String>,
}

fn validate_native_artifact(
    path: &Path,
    expected_soname: &str,
    required_dependencies: &[&str],
) -> Result<(), PipelineError> {
    let dynamic = elf_dynamic(path)?;
    if dynamic.soname.as_deref() != Some(expected_soname) {
        return Err(PipelineError::OutputValidation(format!(
            "{} SONAME is {:?}, expected {expected_soname}",
            path.display(),
            dynamic.soname
        )));
    }
    for dependency in required_dependencies {
        if !dynamic.needed.iter().any(|value| value == dependency) {
            return Err(PipelineError::OutputValidation(format!(
                "{} does not depend on {dependency}",
                path.display()
            )));
        }
    }
    for dependency in &dynamic.needed {
        let lower = dependency.to_ascii_lowercase();
        if dependency.contains(['/', '\\'])
            || dependency.contains(':')
            || lower.contains("target")
            || lower.ends_with(".dll")
        {
            return Err(PipelineError::OutputValidation(format!(
                "{} contains non-Android DT_NEEDED {dependency}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn elf_dynamic(path: &Path) -> Result<ElfDynamic, PipelineError> {
    let mut file = File::open(path)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(PipelineError::OutputValidation(format!(
            "{} is not little-endian ELF64",
            path.display()
        )));
    }
    let program_offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let entry_size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let entry_count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if entry_size < 56 || entry_count == 0 || entry_count > 256 {
        return Err(PipelineError::OutputValidation(format!(
            "{} has an invalid program table",
            path.display()
        )));
    }
    let mut load_segments = Vec::new();
    let mut dynamic_segment = None;
    for index in 0..entry_count {
        file.seek(SeekFrom::Start(program_offset + index * entry_size))?;
        let mut program = [0_u8; 56];
        file.read_exact(&mut program)?;
        let kind = u32::from_le_bytes(program[0..4].try_into().unwrap());
        let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let virtual_address = u64::from_le_bytes(program[16..24].try_into().unwrap());
        let file_size = u64::from_le_bytes(program[32..40].try_into().unwrap());
        if kind == 1 {
            load_segments.push((virtual_address, offset, file_size));
        } else if kind == 2 {
            dynamic_segment = Some((offset, file_size));
        }
    }
    let (dynamic_offset, dynamic_size) = dynamic_segment.ok_or_else(|| {
        PipelineError::OutputValidation(format!("{} has no PT_DYNAMIC", path.display()))
    })?;
    if dynamic_size > 4 * 1024 * 1024 || dynamic_size % 16 != 0 {
        return Err(PipelineError::OutputValidation(format!(
            "{} has an invalid dynamic table",
            path.display()
        )));
    }
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut string_virtual_address = None;
    let mut string_size = None;
    for index in 0..(dynamic_size / 16) {
        file.seek(SeekFrom::Start(dynamic_offset + index * 16))?;
        let mut entry = [0_u8; 16];
        file.read_exact(&mut entry)?;
        let tag = i64::from_le_bytes(entry[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        match tag {
            0 => break,
            1 => needed_offsets.push(value),
            5 => string_virtual_address = Some(value),
            10 => string_size = Some(value),
            14 => soname_offset = Some(value),
            _ => {}
        }
    }
    let string_virtual_address = string_virtual_address.ok_or_else(|| {
        PipelineError::OutputValidation(format!("{} has no DT_STRTAB", path.display()))
    })?;
    let string_size = string_size.ok_or_else(|| {
        PipelineError::OutputValidation(format!("{} has no DT_STRSZ", path.display()))
    })?;
    if string_size == 0 || string_size > 4 * 1024 * 1024 {
        return Err(PipelineError::OutputValidation(format!(
            "{} has an invalid dynamic string table",
            path.display()
        )));
    }
    let string_file_offset = load_segments
        .iter()
        .find_map(|(virtual_address, offset, file_size)| {
            let relative = string_virtual_address.checked_sub(*virtual_address)?;
            (relative < *file_size).then_some(offset + relative)
        })
        .ok_or_else(|| {
            PipelineError::OutputValidation(format!(
                "{} DT_STRTAB is outside PT_LOAD",
                path.display()
            ))
        })?;
    file.seek(SeekFrom::Start(string_file_offset))?;
    let mut strings = vec![0_u8; string_size as usize];
    file.read_exact(&mut strings)?;
    let read_string = |offset: u64| -> Result<String, PipelineError> {
        let offset = usize::try_from(offset).map_err(|_| {
            PipelineError::OutputValidation("ELF string offset does not fit usize".into())
        })?;
        let tail = strings.get(offset..).ok_or_else(|| {
            PipelineError::OutputValidation("ELF string offset is out of bounds".into())
        })?;
        let end = tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
            PipelineError::OutputValidation("unterminated ELF dynamic string".into())
        })?;
        String::from_utf8(tail[..end].to_vec())
            .map_err(|_| PipelineError::OutputValidation("ELF dynamic string is not UTF-8".into()))
    };
    Ok(ElfDynamic {
        needed: needed_offsets
            .into_iter()
            .map(&read_string)
            .collect::<Result<_, _>>()?,
        soname: soname_offset.map(read_string).transpose()?,
    })
}

fn publish_noclobber(staged: &Path, output: &Path) -> Result<(), PipelineError> {
    let parent = output
        .parent()
        .ok_or_else(|| PipelineError::OutputValidation("output has no parent directory".into()))?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    io::copy(&mut File::open(staged)?, temporary.as_file_mut())?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(output)
        .map_err(|error| PipelineError::Io(error.error))?;
    Ok(())
}

fn verify_embedded_payloads(
    extracted: &Path,
    manifest: &CompatibilityManifest,
    workspace: &Path,
) -> Result<(), PipelineError> {
    for (name, value) in &manifest.il2cpp_fields {
        let offset = usize::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|_| {
            PipelineError::PayloadMismatch(format!("invalid field offset for {name}"))
        })?;
        if offset == 0 || offset > 0x10_000 {
            return Err(PipelineError::PayloadMismatch(format!(
                "out-of-range field offset for {name}"
            )));
        }
    }
    let native = workspace.join("verified-libil2cpp.so");
    extract_zip_member(
        &extracted.join("config.arm64_v8a.apk"),
        "lib/arm64-v8a/libil2cpp.so",
        &native,
    )?;
    let actual_native = sha256_file(&native)?;
    if !actual_native.eq_ignore_ascii_case(&manifest.source.il2cpp.sha256) {
        return Err(PipelineError::PayloadMismatch(format!(
            "libil2cpp.so SHA-256 {actual_native}"
        )));
    }
    let build_id = elf_gnu_build_id(&native)?;
    if !build_id.eq_ignore_ascii_case(&manifest.source.il2cpp.build_id) {
        return Err(PipelineError::PayloadMismatch(format!(
            "libil2cpp.so build-id {build_id}"
        )));
    }
    let mut image = File::open(&native)?;
    for fingerprint in manifest
        .il2cpp_hooks
        .iter()
        .chain(&manifest.il2cpp_dependencies)
    {
        let rva =
            usize::from_str_radix(fingerprint.rva.trim_start_matches("0x"), 16).map_err(|_| {
                PipelineError::PayloadMismatch(format!("invalid RVA for {}", fingerprint.name))
            })?;
        let expected = hex::decode(&fingerprint.prologue).map_err(|_| {
            PipelineError::PayloadMismatch(format!("invalid prologue for {}", fingerprint.name))
        })?;
        if expected.len() != 16 {
            return Err(PipelineError::PayloadMismatch(format!(
                "non-16-byte prologue for {}",
                fingerprint.name
            )));
        }
        let file_offset = elf_rva_to_file_offset(&mut image, rva as u64, 16)?;
        let mut actual = [0_u8; 16];
        image.seek(SeekFrom::Start(file_offset))?;
        image.read_exact(&mut actual)?;
        if actual.as_slice() != expected {
            return Err(PipelineError::PayloadMismatch(format!(
                "IL2CPP prologue {} at 0x{rva:X}",
                fingerprint.name
            )));
        }
    }

    let metadata = workspace.join("verified-global-metadata.dat");
    extract_zip_member(
        &extracted.join("base_assets.apk"),
        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
        &metadata,
    )?;
    let actual_metadata = sha256_file(&metadata)?;
    if !actual_metadata.eq_ignore_ascii_case(&manifest.source.global_metadata.sha256) {
        return Err(PipelineError::PayloadMismatch(format!(
            "global-metadata.dat SHA-256 {actual_metadata}"
        )));
    }
    Ok(())
}

fn elf_rva_to_file_offset(
    file: &mut File,
    rva: u64,
    required_size: u64,
) -> Result<u64, PipelineError> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(PipelineError::PayloadMismatch(
            "libil2cpp.so is not little-endian ELF64".into(),
        ));
    }
    let program_offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let entry_size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let entry_count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if entry_size < 56 || entry_count > 256 {
        return Err(PipelineError::PayloadMismatch(
            "invalid ELF program table".into(),
        ));
    }
    let rva_end = rva.checked_add(required_size).ok_or_else(|| {
        PipelineError::PayloadMismatch(format!("overflowing IL2CPP RVA 0x{rva:X}"))
    })?;
    for index in 0..entry_count {
        file.seek(SeekFrom::Start(program_offset + index * entry_size))?;
        let mut program = [0_u8; 56];
        file.read_exact(&mut program)?;
        let kind = u32::from_le_bytes(program[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(program[4..8].try_into().unwrap());
        if kind != 1 || flags & 1 == 0 {
            continue;
        }
        let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let virtual_address = u64::from_le_bytes(program[16..24].try_into().unwrap());
        let file_size = u64::from_le_bytes(program[32..40].try_into().unwrap());
        let virtual_end = virtual_address.checked_add(file_size).ok_or_else(|| {
            PipelineError::PayloadMismatch("overflowing ELF executable segment".into())
        })?;
        if rva >= virtual_address && rva_end <= virtual_end {
            return Ok(offset + (rva - virtual_address));
        }
    }
    Err(PipelineError::PayloadMismatch(format!(
        "IL2CPP RVA 0x{rva:X} is not backed by an executable ELF segment"
    )))
}

fn elf_gnu_build_id(path: &Path) -> Result<String, PipelineError> {
    let mut file = File::open(path)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(PipelineError::PayloadMismatch(
            "libil2cpp.so is not little-endian ELF64".into(),
        ));
    }
    let program_offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let entry_size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let entry_count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if entry_size < 56 || entry_count > 256 {
        return Err(PipelineError::PayloadMismatch(
            "invalid ELF program table".into(),
        ));
    }
    for index in 0..entry_count {
        file.seek(SeekFrom::Start(program_offset + index * entry_size))?;
        let mut program = [0_u8; 56];
        file.read_exact(&mut program)?;
        if u32::from_le_bytes(program[0..4].try_into().unwrap()) != 4 {
            continue;
        }
        let note_offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let note_size = u64::from_le_bytes(program[32..40].try_into().unwrap());
        if note_size > 64 * 1024 {
            return Err(PipelineError::PayloadMismatch("oversized ELF note".into()));
        }
        file.seek(SeekFrom::Start(note_offset))?;
        let mut note = vec![0_u8; note_size as usize];
        file.read_exact(&mut note)?;
        let mut cursor = 0_usize;
        while cursor + 12 <= note.len() {
            let namesz = u32::from_le_bytes(note[cursor..cursor + 4].try_into().unwrap()) as usize;
            let descsz =
                u32::from_le_bytes(note[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            let note_type = u32::from_le_bytes(note[cursor + 8..cursor + 12].try_into().unwrap());
            cursor += 12;
            let name_end = cursor.saturating_add(namesz);
            let name_padded = name_end.saturating_add(3) & !3;
            let desc_end = name_padded.saturating_add(descsz);
            let desc_padded = desc_end.saturating_add(3) & !3;
            if desc_padded > note.len() {
                break;
            }
            if note_type == 3 && note[cursor..name_end].starts_with(b"GNU") {
                return Ok(hex::encode_upper(&note[name_padded..desc_end]));
            }
            cursor = desc_padded;
        }
    }
    Err(PipelineError::PayloadMismatch(
        "libil2cpp.so has no GNU build-id".into(),
    ))
}

fn run_checked(
    program: &Path,
    arguments: &[std::ffi::OsString],
    timeout: Duration,
) -> Result<(), PipelineError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = wait_for_child(&mut child, program, timeout)?;
    if !status.success() {
        return Err(PipelineError::Tool {
            program: program.display().to_string(),
            status: status.code().unwrap_or(-1),
        });
    }
    Ok(())
}

fn run_capture_checked(
    program: &Path,
    arguments: &[std::ffi::OsString],
    timeout: Duration,
) -> Result<String, PipelineError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| PipelineError::OutputValidation("failed to capture tool stdout".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| PipelineError::OutputValidation("failed to capture tool stderr".into()))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = wait_for_child(&mut child, program, timeout)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| PipelineError::OutputValidation("stdout reader panicked".into()))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| PipelineError::OutputValidation("stderr reader panicked".into()))??;
    if !status.success() {
        return Err(PipelineError::Tool {
            program: program.display().to_string(),
            status: status.code().unwrap_or(-1),
        });
    }
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    Ok(text)
}

fn wait_for_child(
    child: &mut Child,
    program: &Path,
    timeout: Duration,
) -> Result<ExitStatus, PipelineError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PipelineError::ToolTimeout {
                program: program.display().to_string(),
                seconds: timeout.as_secs(),
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn apk_signer_fingerprint(
    apksigner: &Path,
    apk: &Path,
    timeout: Duration,
) -> Result<String, PipelineError> {
    let output = run_capture_checked(
        apksigner,
        &[
            "verify".into(),
            "--print-certs".into(),
            apk.as_os_str().into(),
        ],
        timeout,
    )?;
    output
        .lines()
        .find_map(|line| {
            let (label, value) = line.split_once(':')?;
            label
                .to_ascii_lowercase()
                .contains("certificate sha-256 digest")
                .then(|| value.trim().to_owned())
        })
        .ok_or_else(|| {
            PipelineError::OutputValidation(format!(
                "apksigner did not report a certificate SHA-256 for {}",
                apk.display()
            ))
        })
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .map(|byte| (byte as char).to_ascii_uppercase())
        .collect()
}

fn validate_transformed_manifest(
    path: &Path,
    application_id: &str,
    old_application_id: &str,
    version_code: i64,
    version_name: &str,
    base: bool,
    label: &str,
) -> Result<(), PipelineError> {
    let xml = fs::read_to_string(path)?;
    for expected in [
        format!("package=\"{application_id}\""),
        format!("android:versionCode=\"{version_code}\""),
        format!("android:versionName=\"{version_name}\""),
    ] {
        if !xml.contains(&expected) {
            return Err(PipelineError::OutputValidation(format!(
                "{} is missing {expected}",
                path.display()
            )));
        }
    }
    if xml.contains(old_application_id) {
        return Err(PipelineError::OutputValidation(format!(
            "{} still contains the retired package identifier",
            path.display()
        )));
    }
    if base {
        for expected in [
            format!("android:label=\"{label}\""),
            "org.guitargirlresuscitation.memorial.MemorialBootstrapProvider".to_owned(),
            "org.guitargirlresuscitation.memorial.MemorialStartupActivity".to_owned(),
            format!("android:authorities=\"{application_id}.ggfm.bootstrap\""),
        ] {
            if !xml.contains(&expected) {
                return Err(PipelineError::OutputValidation(format!(
                    "base manifest is missing {expected}"
                )));
            }
        }
    }
    Ok(())
}

struct SignedManifestExpectation<'a> {
    application_id: &'a str,
    retired_application_id: &'a str,
    version_code: i64,
    version_name: &'a str,
    base: bool,
    label: &'a str,
}

fn validate_signed_manifest(
    aapt2: &Path,
    apk: &Path,
    expected: SignedManifestExpectation<'_>,
    timeout: Duration,
) -> Result<(), PipelineError> {
    let SignedManifestExpectation {
        application_id,
        retired_application_id,
        version_code,
        version_name,
        base,
        label,
    } = expected;
    let dump = run_capture_checked(
        aapt2,
        &[
            "dump".into(),
            "xmltree".into(),
            "--file".into(),
            "AndroidManifest.xml".into(),
            apk.as_os_str().into(),
        ],
        timeout,
    )?;
    for expected in [
        format!("package=\"{application_id}\""),
        format!("versionCode(0x0101021b)={version_code}"),
        format!("versionName(0x0101021c)=\"{version_name}\""),
    ] {
        if !dump.contains(&expected) {
            return Err(PipelineError::OutputValidation(format!(
                "signed {} manifest is missing {expected}",
                apk.display()
            )));
        }
    }
    if dump.contains(retired_application_id) {
        return Err(PipelineError::OutputValidation(format!(
            "signed {} manifest still contains the retired package identifier",
            apk.display()
        )));
    }
    if base {
        for expected in [
            format!("label(0x01010001)=\"{label}\""),
            "org.guitargirlresuscitation.memorial.MemorialBootstrapProvider".to_owned(),
            "org.guitargirlresuscitation.memorial.MemorialStartupActivity".to_owned(),
            format!("authorities(0x01010018)=\"{application_id}.ggfm.bootstrap\""),
        ] {
            if !dump.contains(&expected) {
                return Err(PipelineError::OutputValidation(format!(
                    "signed base manifest is missing {expected}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_injected_payloads(
    signed_dir: &Path,
    base_name: &str,
    expected_dex: &str,
    transformed_table_bundle_sha256: &str,
) -> Result<(), PipelineError> {
    validate_zip_entries(
        &signed_dir.join(base_name),
        &[
            expected_dex,
            "assets/ggfm/policy.json",
            "assets/ggfm/master.sqlite",
            "assets/ggfm/master-transform-report.json",
        ],
    )?;
    validate_zip_entries(
        &signed_dir.join("config.arm64_v8a.apk"),
        &[
            "lib/arm64-v8a/libggfm_bootstrap.so",
            "lib/arm64-v8a/libdobby.so",
            "lib/arm64-v8a/libggfm_server.so",
        ],
    )?;
    let actual = zip_member_sha256(
        &signed_dir.join("base_assets.apk"),
        "assets/AssetBundles/Android/table/table_db.ab",
    )?;
    if !actual.eq_ignore_ascii_case(transformed_table_bundle_sha256) {
        return Err(PipelineError::OutputValidation(format!(
            "signed base_assets table bundle is {actual}, expected {transformed_table_bundle_sha256}"
        )));
    }
    Ok(())
}

fn zip_member_sha256(path: &Path, member: &str) -> Result<String, PipelineError> {
    use sha2::{Digest, Sha256};
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let mut entry = archive.by_name(member)?;
    let mut hasher = Sha256::new();
    io::copy(&mut entry, &mut hasher)?;
    Ok(hex::encode_upper(hasher.finalize()))
}

fn validate_zip_entries(path: &Path, required: &[&str]) -> Result<(), PipelineError> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let names = (0..archive.len())
        .map(|index| archive.by_index(index).map(|entry| entry.name().to_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for name in required {
        if !names.contains(*name) {
            return Err(PipelineError::OutputValidation(format!(
                "{} is missing {name}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn enforce_work_quota(root: &Path, limit: u64) -> Result<(), PipelineError> {
    let mut pending = vec![root.to_owned()];
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(PipelineError::OutputValidation(format!(
                    "patch workspace unexpectedly contains symlink {}",
                    entry.path().display()
                )));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                total = total.saturating_add(entry.metadata()?.len());
                if total > limit {
                    return Err(PipelineError::WorkQuota {
                        actual: total,
                        limit,
                    });
                }
            }
        }
    }
    Ok(())
}

fn extract_xapk(source: &Path, destination: &Path) -> Result<(), PipelineError> {
    let mut archive = ZipArchive::new(File::open(source)?)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let output = destination.join(entry.name());
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        io::copy(&mut entry, &mut File::create(output)?)?;
    }
    Ok(())
}

fn extract_zip_member(archive: &Path, name: &str, output: &Path) -> Result<(), PipelineError> {
    let mut archive = ZipArchive::new(File::open(archive)?)?;
    let mut entry = archive.by_name(name)?;
    io::copy(&mut entry, &mut File::create(output)?)?;
    Ok(())
}

fn next_dex_name(apk: &Path) -> Result<String, PipelineError> {
    let mut archive = ZipArchive::new(File::open(apk)?)?;
    let mut used = BTreeSet::new();
    for index in 0..archive.len() {
        let name = archive.by_index(index)?.name().to_owned();
        if name == "classes.dex" {
            used.insert(1_u32);
        } else if let Some(number) = name
            .strip_prefix("classes")
            .and_then(|value| value.strip_suffix(".dex"))
            .and_then(|value| value.parse().ok())
        {
            used.insert(number);
        }
    }
    let next = used.last().copied().unwrap_or(1) + 1;
    Ok(format!("classes{next}.dex"))
}

fn append_zip_entries(
    source: &Path,
    output: &Path,
    additions: &[(&PathBuf, String)],
) -> Result<(), PipelineError> {
    let names: BTreeSet<_> = additions.iter().map(|(_, name)| name.as_str()).collect();
    let mut input = ZipArchive::new(File::open(source)?)?;
    let mut writer = ZipWriter::new(File::create(output)?);
    for index in 0..input.len() {
        let entry = input.by_index(index)?;
        if !names.contains(entry.name()) {
            writer.raw_copy_file(entry)?;
        }
    }
    for (path, name) in additions {
        // The original manifest sets android:extractNativeLibs="false". Android
        // therefore requires native libraries to remain uncompressed so that
        // zipalign can page-align and mmap them directly from the split APK.
        let compression = if name.starts_with("lib/") && name.ends_with(".so") {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        let options = SimpleFileOptions::default().compression_method(compression);
        writer.start_file(name, options)?;
        io::copy(&mut File::open(path)?, &mut writer)?;
    }
    writer.finish()?;
    Ok(())
}

fn build_xapk(
    extracted: &Path,
    signed: &Path,
    manifest: &CompatibilityManifest,
    plan: &PatchPlan,
    version_code: i64,
    version_name: &str,
    output: &Path,
) -> Result<(), PipelineError> {
    let original_manifest = fs::read(extracted.join("manifest.json"))?;
    let mut document: Value = serde_json::from_slice(&original_manifest)?;
    rewrite_json_strings(
        &mut document,
        "com.neowiz.game.guitargirl",
        &plan.application_id,
    );
    document["package_name"] = plan.application_id.clone().into();
    document["name"] = plan.application_label.clone().into();
    document["version_code"] = version_code.to_string().into();
    document["version_name"] = version_name.into();
    if let Some(names) = document
        .get_mut("locales_name")
        .and_then(Value::as_object_mut)
    {
        for name in names.values_mut() {
            *name = plan.application_label.clone().into();
        }
    }
    if let Some(apks) = document.get_mut("split_apks").and_then(Value::as_array_mut) {
        for apk in apks {
            if apk.get("id").and_then(Value::as_str) == Some("base") {
                apk["file"] = format!("{}.apk", plan.application_id).into();
            }
        }
    }
    document["total_size"] = manifest
        .source
        .splits
        .iter()
        .map(|split| fs::metadata(signed.join(&split.name)).map(|metadata| metadata.len()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u64>()
        .into();
    let mut writer = ZipWriter::new(File::create(output)?);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    writer.start_file("manifest.json", options)?;
    writer.write_all(&serde_json::to_vec_pretty(&document)?)?;
    if extracted.join("icon.png").exists() {
        writer.start_file("icon.png", options)?;
        io::copy(&mut File::open(extracted.join("icon.png"))?, &mut writer)?;
    }
    for split in &manifest.source.splits {
        let output_name = if split.name != "config.arm64_v8a.apk" && split.name != "base_assets.apk"
        {
            format!("{}.apk", plan.application_id)
        } else {
            split.name.clone()
        };
        writer.start_file(output_name, options)?;
        io::copy(&mut File::open(signed.join(&split.name))?, &mut writer)?;
    }
    writer.finish()?;
    Ok(())
}

fn rewrite_json_strings(document: &mut Value, from: &str, to: &str) {
    match document {
        Value::String(value) => {
            if value.contains(from) {
                *value = value.replace(from, to);
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_json_strings(value, from, to);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                rewrite_json_strings(value, from, to);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn validate_output_xapk(
    output: &Path,
    manifest: &CompatibilityManifest,
    plan: &PatchPlan,
    version_code: i64,
    version_name: &str,
    base_name: &str,
) -> Result<(), PipelineError> {
    let mut archive = ZipArchive::new(File::open(output)?)?;
    let mut names = BTreeSet::new();
    let mut apk_names = BTreeSet::new();
    for index in 0..archive.len() {
        let name = archive.by_index(index)?.name().to_owned();
        if !names.insert(name.clone()) {
            return Err(PipelineError::OutputValidation(format!(
                "duplicate XAPK entry {name}"
            )));
        }
        if name.ends_with(".apk") {
            apk_names.insert(name);
        }
    }
    let expected_apks: BTreeSet<String> = manifest
        .source
        .splits
        .iter()
        .map(|split| {
            if split.name == base_name {
                format!("{}.apk", plan.application_id)
            } else {
                split.name.clone()
            }
        })
        .collect();
    if apk_names != expected_apks {
        return Err(PipelineError::OutputValidation(format!(
            "XAPK split names differ: actual={apk_names:?} expected={expected_apks:?}"
        )));
    }
    let document: Value = {
        let mut entry = archive.by_name("manifest.json")?;
        serde_json::from_reader(&mut entry)?
    };
    if serde_json::to_string(&document)?.contains("com.neowiz.game.guitargirl") {
        return Err(PipelineError::OutputValidation(
            "XAPK manifest still contains the retired package identifier".into(),
        ));
    }
    let actual_package = document.get("package_name").and_then(Value::as_str);
    let actual_version_code = document.get("version_code").and_then(Value::as_str);
    let actual_version_name = document.get("version_name").and_then(Value::as_str);
    if actual_package != Some(plan.application_id.as_str())
        || actual_version_code != Some(version_code.to_string().as_str())
        || actual_version_name != Some(version_name)
    {
        return Err(PipelineError::OutputValidation(
            "XAPK manifest package or version does not match signed splits".into(),
        ));
    }
    let listed_files: BTreeSet<&str> = document
        .get("split_apks")
        .and_then(Value::as_array)
        .ok_or_else(|| PipelineError::OutputValidation("XAPK has no split_apks array".into()))?
        .iter()
        .filter_map(|entry| entry.get("file").and_then(Value::as_str))
        .collect();
    if listed_files != expected_apks.iter().map(String::as_str).collect() {
        return Err(PipelineError::OutputValidation(
            "XAPK manifest split list does not match archive entries".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod output_validation_tests {
    use super::*;

    #[test]
    fn il2cpp_runtime_rva_is_mapped_through_executable_load_segment() {
        let mut file = NamedTempFile::new().unwrap();
        let mut elf = vec![0_u8; 0x200];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let program = &mut elf[64..120];
        program[0..4].copy_from_slice(&1_u32.to_le_bytes());
        program[4..8].copy_from_slice(&5_u32.to_le_bytes());
        program[8..16].copy_from_slice(&0x100_u64.to_le_bytes());
        program[16..24].copy_from_slice(&0x4000_u64.to_le_bytes());
        program[32..40].copy_from_slice(&0x100_u64.to_le_bytes());
        file.write_all(&elf).unwrap();
        file.flush().unwrap();
        let mut opened = File::open(file.path()).unwrap();
        assert_eq!(
            elf_rva_to_file_offset(&mut opened, 0x4010, 16).unwrap(),
            0x110
        );
        assert!(matches!(
            elf_rva_to_file_offset(&mut opened, 0x3fff, 16),
            Err(PipelineError::PayloadMismatch(_))
        ));
    }

    #[test]
    fn server_policy_fingerprint_must_be_embedded() {
        let file = NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            b"prefix341D6AD64E09B33CA8D61311DD65EC2B08C7D66CE16A87F23ABFAFC772233CCEsuffix",
        )
        .unwrap();
        assert!(
            validate_server_policy_fingerprint(
                file.path(),
                "341d6ad64e09b33ca8d61311dd65ec2b08c7d66ce16a87f23abfafc772233cce"
            )
            .is_ok()
        );
        assert!(matches!(
            validate_server_policy_fingerprint(file.path(), &"0".repeat(64)),
            Err(PipelineError::ServerPolicyMismatch(_))
        ));
    }

    #[test]
    fn stale_bootstrap_is_rejected_even_when_server_policy_matches() {
        let server = NamedTempFile::new().unwrap();
        let bootstrap = NamedTempFile::new().unwrap();
        let policy = "A".repeat(64);
        fs::write(server.path(), policy.as_bytes()).unwrap();
        fs::write(bootstrap.path(), "B".repeat(64)).unwrap();
        assert!(matches!(
            validate_runtime_policy_fingerprints(server.path(), bootstrap.path(), &policy),
            Err(PipelineError::OutputValidation(_))
        ));
        fs::write(bootstrap.path(), policy.as_bytes()).unwrap();
        validate_runtime_policy_fingerprints(server.path(), bootstrap.path(), &policy).unwrap();
    }

    #[test]
    fn signer_fingerprint_normalization_is_format_independent() {
        assert_eq!(
            normalize_fingerprint("aa:BB 01"),
            normalize_fingerprint("AABB01")
        );
    }

    #[test]
    fn transformed_manifest_rejects_retired_identifier() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("AndroidManifest.xml");
        fs::write(
            &manifest,
            concat!(
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" ",
                "package=\"org.guitargirlresuscitation.memorial\" ",
                "android:versionCode=\"800001\" android:versionName=\"8.0.0-memorial.1\">",
                "<application android:label=\"Guitar Girl Fan Memorial Build\" ",
                "android:authorities=\"com.neowiz.game.guitargirl.bad\" />",
                "</manifest>"
            ),
        )
        .unwrap();
        assert!(matches!(
            validate_transformed_manifest(
                &manifest,
                "org.guitargirlresuscitation.memorial",
                "com.neowiz.game.guitargirl",
                800001,
                "8.0.0-memorial.1",
                false,
                "Guitar Girl Fan Memorial Build",
            ),
            Err(PipelineError::OutputValidation(_))
        ));
    }

    #[test]
    fn xapk_metadata_string_rewrite_is_recursive() {
        let mut value = serde_json::json!({
            "package": "com.neowiz.game.guitargirl",
            "permissions": ["com.neowiz.game.guitargirl.permission.C2D_MESSAGE"],
            "unchanged": 7
        });
        rewrite_json_strings(
            &mut value,
            "com.neowiz.game.guitargirl",
            "org.guitargirlresuscitation.memorial",
        );
        assert_eq!(
            value["permissions"][0],
            "org.guitargirlresuscitation.memorial.permission.C2D_MESSAGE"
        );
        assert_eq!(value["unchanged"], 7);
    }

    #[test]
    fn workspace_disk_quota_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("nested")).unwrap();
        fs::write(temporary.path().join("first"), vec![0_u8; 8]).unwrap();
        fs::write(temporary.path().join("nested/second"), vec![0_u8; 8]).unwrap();
        assert!(matches!(
            enforce_work_quota(temporary.path(), 15),
            Err(PipelineError::WorkQuota { .. })
        ));
        enforce_work_quota(temporary.path(), 16).unwrap();
    }

    #[test]
    fn injected_native_libraries_are_stored_for_direct_mmap() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.apk");
        let output = temporary.path().join("output.apk");
        let native = temporary.path().join("libggfm_server.so");
        let asset = temporary.path().join("policy.json");
        fs::write(&native, b"native-library").unwrap();
        fs::write(&asset, b"{}").unwrap();

        let mut writer = ZipWriter::new(File::create(&source).unwrap());
        writer
            .start_file(
                "AndroidManifest.xml",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(b"manifest").unwrap();
        writer.finish().unwrap();

        append_zip_entries(
            &source,
            &output,
            &[
                (&native, "lib/arm64-v8a/libggfm_server.so".into()),
                (&asset, "assets/ggfm/policy.json".into()),
            ],
        )
        .unwrap();

        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        assert_eq!(
            archive
                .by_name("lib/arm64-v8a/libggfm_server.so")
                .unwrap()
                .compression(),
            CompressionMethod::Stored
        );
        assert_eq!(
            archive
                .by_name("assets/ggfm/policy.json")
                .unwrap()
                .compression(),
            CompressionMethod::Deflated
        );
    }

    #[cfg(windows)]
    #[test]
    fn external_tool_timeout_terminates_child() {
        let result = run_checked(
            Path::new("ping.exe"),
            &["-n".into(), "3".into(), "127.0.0.1".into()],
            Duration::from_millis(50),
        );
        assert!(matches!(result, Err(PipelineError::ToolTimeout { .. })));
    }
}
