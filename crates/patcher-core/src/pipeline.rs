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

#[path = "pipeline_supplement.rs"]
mod supplement;
pub use supplement::NativeSupplement;

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
    pub additional_native: Option<NativeSupplement>,
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
    #[error("invalid Android release version: {0}")]
    Version(#[from] crate::VersionError),
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
        let version =
            crate::AndroidVersion::deployment(memorial_revision, plan.deployment_revision)?;
        if output.exists() {
            return Err(PipelineError::OutputExists(output.to_owned()));
        }
        self.validate_artifacts()?;
        for path in [&self.artifacts.bootstrap_so, &self.artifacts.dobby_so, &self.artifacts.server_so] {
            validate_elf_abi(path, manifest.source.abi)?;
        }
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
        let mut output_manifest = manifest.clone();
        if let Some(extra) = &self.artifacts.additional_native {
            let profile = extra.stage(manifest, &self.artifacts.policy_sha256, &extracted, workspace.path())?;
            let split = profile.source.splits.iter().find(|s| s.name == profile.source.abi.split_name())
                .ok_or(PipelineError::MissingBase)?.clone();
            output_manifest.source.splits.push(split);
        }

        let base_name = manifest
            .source
            .splits
            .iter()
            .map(|split| split.name.as_str())
            .find(|name| *name != manifest.source.abi.split_name() && *name != "base_assets.apk")
            .ok_or(PipelineError::MissingBase)?;
        let version_code = i64::from(version.version_code);
        let version_name = version.version_name;
        let unsigned_dir = workspace.path().join("unsigned");
        let signed_dir = workspace.path().join("signed");
        let framework_dir = workspace.path().join("apktool-framework");
        fs::create_dir(&unsigned_dir)?;
        fs::create_dir(&signed_dir)?;
        fs::create_dir(&framework_dir)?;

        let mut rebuilt = BTreeMap::new();
        for split in &output_manifest.source.splits {
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
        let update_provenance = workspace.path().join("update-source.json");
        fs::write(
            &update_provenance,
            serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "origin": plan.update_origin,
                "applicationId": plan.application_id,
                "signerSha256": normalize_fingerprint(&plan.signer_fingerprint),
                "versionCode": version.version_code,
            }))?,
        )?;
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
                    &update_provenance,
                    "assets/ggfm/update-source.json".to_owned(),
                ),
                (
                    &master_transform_report,
                    "assets/ggfm/master-transform-report.json".to_owned(),
                ),
            ],
        )?;
        rebuilt.insert(base_name.to_owned(), patched_base);

        let arm = rebuilt
            .get(manifest.source.abi.split_name())
            .ok_or_else(|| PipelineError::MissingXapkEntry(manifest.source.abi.split_name().into()))?;
        let patched_arm = unsigned_dir.join("native-injected.apk");
        append_zip_entries(
            arm,
            &patched_arm,
            &[
                (
                    &self.artifacts.bootstrap_so,
                    manifest.source.abi.library("libggfm_bootstrap.so"),
                ),
                (&self.artifacts.dobby_so, manifest.source.abi.library("libdobby.so")),
                (
                    &self.artifacts.server_so,
                    manifest.source.abi.library("libggfm_server.so"),
                ),
            ],
        )?;
        rebuilt.insert(manifest.source.abi.split_name().into(), patched_arm);
        if let Some(extra) = &self.artifacts.additional_native {
            extra.inject(&mut rebuilt, &unsigned_dir)?;
        }
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
            manifest.source.abi,
            base_name,
            &bootstrap_dex_name,
            &transformed_table_bundle_sha256,
        )?;
        if self.artifacts.additional_native.is_some() {
            validate_injected_payloads(&signed_dir, crate::manifest::AndroidAbi::ArmV7,
                base_name, &bootstrap_dex_name, &transformed_table_bundle_sha256)?;
        }

        let staged_output = workspace.path().join("validated-output.xapk");
        build_xapk(
            &extracted,
            &signed_dir,
            &output_manifest,
            plan,
            version_code,
            &version_name,
            &staged_output,
        )?;
        validate_output_xapk(
            &staged_output,
            &output_manifest,
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
    let programs = elf_programs(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 6];
    file.read_exact(&mut header)?;
    let elf32 = header[4] == 1;
    let dynamic_entry_size = if elf32 { 8 } else { 16 };
    let mut load_segments = Vec::new();
    let mut dynamic_segment = None;
    for program in programs {
        let ElfProgram { kind, offset, virtual_address, file_size, .. } = program;
        if kind == 1 {
            load_segments.push((virtual_address, offset, file_size));
        } else if kind == 2 {
            dynamic_segment = Some((offset, file_size));
        }
    }
    let (dynamic_offset, dynamic_size) = dynamic_segment.ok_or_else(|| {
        PipelineError::OutputValidation(format!("{} has no PT_DYNAMIC", path.display()))
    })?;
    if dynamic_size > 4 * 1024 * 1024 || dynamic_size % dynamic_entry_size != 0 {
        return Err(PipelineError::OutputValidation(format!(
            "{} has an invalid dynamic table",
            path.display()
        )));
    }
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut string_virtual_address = None;
    let mut string_size = None;
    for index in 0..(dynamic_size / dynamic_entry_size) {
        file.seek(SeekFrom::Start(dynamic_offset + index * dynamic_entry_size))?;
        let mut entry = [0_u8; 16];
        file.read_exact(&mut entry[..dynamic_entry_size as usize])?;
        let (tag, value) = if elf32 {
            (i32::from_le_bytes(entry[0..4].try_into().unwrap()) as i64,
             u32::from_le_bytes(entry[4..8].try_into().unwrap()) as u64)
        } else {
            (i64::from_le_bytes(entry[0..8].try_into().unwrap()),
             u64::from_le_bytes(entry[8..16].try_into().unwrap()))
        };
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
            let end = relative.checked_add(string_size)?;
            if end <= *file_size { offset.checked_add(relative) } else { None }
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
        &extracted.join(manifest.source.abi.split_name()),
        &manifest.source.abi.library("libil2cpp.so"),
        &native,
    )?;
    validate_elf_abi(&native, manifest.source.abi)?;
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

struct ElfProgram {
    kind: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
}

fn validate_elf_abi(path: &Path, abi: crate::manifest::AndroidAbi) -> Result<(), PipelineError> {
    let mut header = [0_u8; 20];
    File::open(path)?.read_exact(&mut header)?;
    let expected = abi.elf_identity();
    let actual = (header[4], u16::from_le_bytes(header[18..20].try_into().unwrap()));
    if &header[..4] != b"\x7fELF" || header[5] != 1 || actual != expected {
        return Err(PipelineError::OutputValidation(format!("{} has wrong ELF ABI for {abi:?}", path.display())));
    }
    Ok(())
}

fn elf_programs(file: &mut File) -> Result<Vec<ElfProgram>, PipelineError> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || !matches!(header[4], 1 | 2) || header[5] != 1 {
        return Err(PipelineError::PayloadMismatch(
            "native library is not little-endian ELF32/ELF64".into(),
        ));
    }
    let elf32 = header[4] == 1;
    let (program_offset, size_at, count_at, minimum_size) = if elf32 {
        (u32::from_le_bytes(header[28..32].try_into().unwrap()) as u64, 42, 44, 32)
    } else {
        (u64::from_le_bytes(header[32..40].try_into().unwrap()), 54, 56, 56)
    };
    let entry_size = u16::from_le_bytes(header[size_at..size_at + 2].try_into().unwrap()) as u64;
    let entry_count = u16::from_le_bytes(header[count_at..count_at + 2].try_into().unwrap()) as u64;
    let image_size = file.metadata()?.len();
    let table_end = entry_size.checked_mul(entry_count).and_then(|size| program_offset.checked_add(size));
    if entry_size < minimum_size || entry_count == 0 || entry_count > 256
        || table_end.is_none_or(|end| end > image_size) {
        return Err(PipelineError::PayloadMismatch(
            "invalid ELF program table".into(),
        ));
    }
    let mut programs = Vec::new();
    for index in 0..entry_count {
        file.seek(SeekFrom::Start(program_offset + index * entry_size))?;
        let mut raw = [0_u8; 56];
        file.read_exact(&mut raw[..minimum_size as usize])?;
        let word = |at| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let wide = |at| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let program = if elf32 {
            ElfProgram { kind: word(0), flags: word(24), offset: word(4) as u64,
                virtual_address: word(8) as u64, file_size: word(16) as u64 }
        } else {
            ElfProgram { kind: word(0), flags: word(4), offset: wide(8),
                virtual_address: wide(16), file_size: wide(32) }
        };
        if program.offset.checked_add(program.file_size).is_none_or(|end| end > image_size) {
            return Err(PipelineError::PayloadMismatch("ELF segment exceeds file".into()));
        }
        programs.push(program);
    }
    Ok(programs)
}

fn elf_rva_to_file_offset(
    file: &mut File,
    rva: u64,
    required_size: u64,
) -> Result<u64, PipelineError> {
    let programs = elf_programs(file)?;
    let rva_end = rva.checked_add(required_size).ok_or_else(|| {
        PipelineError::PayloadMismatch(format!("overflowing IL2CPP RVA 0x{rva:X}"))
    })?;
    for program in programs {
        let ElfProgram { kind, flags, offset, virtual_address, file_size } = program;
        if kind != 1 || flags & 1 == 0 {
            continue;
        }
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
    for program in elf_programs(&mut file)? {
        if program.kind != 4 {
            continue;
        }
        let note_offset = program.offset;
        let note_size = program.file_size;
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
    abi: crate::manifest::AndroidAbi,
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
            "assets/ggfm/update-source.json",
            "assets/ggfm/master-transform-report.json",
        ],
    )?;
    validate_zip_entries(
        &signed_dir.join(abi.split_name()),
        &[
            &abi.library("libggfm_bootstrap.so"),
            &abi.library("libdobby.so"),
            &abi.library("libggfm_server.so"),
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
        let mut entry = input.by_index(index)?;
        if !names.contains(entry.name()) {
            if entry.name().starts_with("lib/") && entry.name().ends_with(".so") {
                // A supplemental original split may have used extraction while
                // the shared base requires mmap. Normalize all native entries,
                // not only our injected libraries; zipalign runs afterwards.
                writer.start_file(entry.name(), SimpleFileOptions::default().compression_method(CompressionMethod::Stored))?;
                io::copy(&mut entry, &mut writer)?;
            } else {
                writer.raw_copy_file(entry)?;
            }
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
    // Derive both lists from the actual output split set, including an optional
    // verified second ABI. Installers must never mistake it for the base APK.
    document["split_apks"] = Value::Array(manifest.source.splits.iter().map(|split| {
        let base = !split.name.starts_with("config.") && split.name != "base_assets.apk";
        serde_json::json!({"id": if base { "base" } else { split.name.trim_end_matches(".apk") },
            "file": if base { format!("{}.apk", plan.application_id) } else { split.name.clone() }})
    }).collect());
    document["split_configs"] = Value::Array(manifest.source.splits.iter()
        .filter(|s| s.name.starts_with("config.") || s.name == "base_assets.apk")
        .map(|s| Value::String(s.name.trim_end_matches(".apk").to_owned())).collect());
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
        let output_name = if !split.name.starts_with("config.") && split.name != "base_assets.apk"
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
    fn universal_xapk_lists_both_architectures_without_renaming_either_as_base() {
        let dir = tempfile::tempdir().unwrap();
        let extracted = dir.path().join("extracted");
        let signed = dir.path().join("signed");
        fs::create_dir(&extracted).unwrap();
        fs::create_dir(&signed).unwrap();
        let mut manifest = CompatibilityManifest::parse(include_bytes!("../../../patch/compatibility/8.0.0.json")).unwrap();
        manifest.source.splits.push(crate::SplitDigest { name: "config.armeabi_v7a.apk".into(), sha256: "AB".repeat(32) });
        let base_name = &manifest.source.splits[0].name;
        for split in &manifest.source.splits { fs::write(signed.join(&split.name), b"test-only").unwrap(); }
        fs::write(extracted.join("manifest.json"), br#"{"package_name":"com.neowiz.game.guitargirl","split_apks":[{"id":"base","file":"old.apk"}],"split_configs":["config.arm64_v8a","base_assets"]}"#).unwrap();
        let plan = PatchPlan { application_id: "org.guitargirlresuscitation.memorial.test".into(),
            application_label: "Test".into(), signer_fingerprint: "AB".repeat(32), cache_key: "test".into(),
            update_origin: None, deployment_revision: None, stages: vec![] };
        let output = dir.path().join("test.xapk");
        build_xapk(&extracted, &signed, &manifest, &plan, 800001, "test", &output).unwrap();
        validate_output_xapk(&output, &manifest, &plan, 800001, "test", base_name).unwrap();
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        let metadata: Value = serde_json::from_reader(archive.by_name("manifest.json").unwrap()).unwrap();
        assert_eq!(metadata["split_configs"].as_array().unwrap().len(), 3);
        assert_eq!(metadata["split_apks"].as_array().unwrap().len(), 4);
        assert_eq!(metadata["total_size"], 36);
    }

    #[test]
    fn native_abi_guard_rejects_mixed_server_and_patch_architectures() {
        use crate::manifest::AndroidAbi;
        let file = NamedTempFile::new().unwrap();
        let mut header = [0_u8; 20];
        header[..6].copy_from_slice(b"\x7fELF\x01\x01");
        header[18..20].copy_from_slice(&40_u16.to_le_bytes());
        fs::write(file.path(), header).unwrap();
        assert!(validate_elf_abi(file.path(), AndroidAbi::ArmV7).is_ok());
        assert!(validate_elf_abi(file.path(), AndroidAbi::Arm64).is_err());
        header[4] = 2;
        header[18..20].copy_from_slice(&183_u16.to_le_bytes());
        fs::write(file.path(), header).unwrap();
        assert!(validate_elf_abi(file.path(), AndroidAbi::Arm64).is_ok());
        assert!(validate_elf_abi(file.path(), AndroidAbi::ArmV7).is_err());
        assert!(serde_json::from_str::<AndroidAbi>("\"x86\"").is_err());
    }

    #[test]
    fn dynamic_dependencies_and_soname_are_consistent_for_both_elf_classes() {
        for elf32 in [true, false] {
            let mut image = vec![0_u8; 0x200];
            image[..6].copy_from_slice(b"\x7fELF\x02\x01");
            image[4] = if elf32 { 1 } else { 2 };
            let stride = if elf32 { 8 } else { 16 };
            if elf32 {
                image[28..32].copy_from_slice(&52_u32.to_le_bytes());
                image[42..44].copy_from_slice(&32_u16.to_le_bytes());
                image[44..46].copy_from_slice(&2_u16.to_le_bytes());
                for (at, kind, offset, address, size) in [(52, 1, 0, 0x1000, 0x200), (84, 2, 0x100, 0x1100, 40)] {
                    for (field, value) in [(0, kind), (4, offset), (8, address), (16, size)] {
                        image[at + field..at + field + 4].copy_from_slice(&(value as u32).to_le_bytes());
                    }
                }
            } else {
                image[32..40].copy_from_slice(&64_u64.to_le_bytes());
                image[54..56].copy_from_slice(&56_u16.to_le_bytes());
                image[56..58].copy_from_slice(&2_u16.to_le_bytes());
                for (at, kind, offset, address, size) in [(64, 1, 0, 0x1000, 0x200), (120, 2, 0x100, 0x1100, 80)] {
                    image[at..at + 4].copy_from_slice(&(kind as u32).to_le_bytes());
                    for (field, value) in [(8, offset), (16, address), (32, size)] {
                        image[at + field..at + field + 8].copy_from_slice(&(value as u64).to_le_bytes());
                    }
                }
            }
            let strings = b"libc.so\0libtest.so\0";
            image[0x180..0x180 + strings.len()].copy_from_slice(strings);
            for (i, (tag, value)) in [(5_u64, 0x1180_u64), (10, strings.len() as u64), (1, 0), (14, 8), (0, 0)].into_iter().enumerate() {
                let at = 0x100 + i * stride;
                if elf32 {
                    image[at..at + 4].copy_from_slice(&(tag as u32).to_le_bytes());
                    image[at + 4..at + 8].copy_from_slice(&(value as u32).to_le_bytes());
                } else {
                    image[at..at + 8].copy_from_slice(&tag.to_le_bytes());
                    image[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
                }
            }
            let file = NamedTempFile::new().unwrap();
            fs::write(file.path(), image).unwrap();
            let dynamic = elf_dynamic(file.path()).unwrap();
            assert_eq!(dynamic.needed, vec!["libc.so"]);
            assert_eq!(dynamic.soname.as_deref(), Some("libtest.so"));
        }
    }

    #[test]
    fn elf32_maps_code_and_reads_build_id_without_elf64_offsets() {
        let mut image = vec![0_u8; 0x200];
        image[..6].copy_from_slice(b"\x7fELF\x01\x01");
        image[18..20].copy_from_slice(&40_u16.to_le_bytes());
        image[28..32].copy_from_slice(&52_u32.to_le_bytes());
        image[42..44].copy_from_slice(&32_u16.to_le_bytes());
        image[44..46].copy_from_slice(&2_u16.to_le_bytes());
        let load = &mut image[52..84];
        load[0..4].copy_from_slice(&1_u32.to_le_bytes());
        load[4..8].copy_from_slice(&0x100_u32.to_le_bytes());
        load[8..12].copy_from_slice(&0x4000_u32.to_le_bytes());
        load[16..20].copy_from_slice(&0x80_u32.to_le_bytes());
        load[24..28].copy_from_slice(&5_u32.to_le_bytes());
        let note = &mut image[84..116];
        note[0..4].copy_from_slice(&4_u32.to_le_bytes());
        note[4..8].copy_from_slice(&0x180_u32.to_le_bytes());
        note[16..20].copy_from_slice(&20_u32.to_le_bytes());
        image[0x180..0x184].copy_from_slice(&4_u32.to_le_bytes());
        image[0x184..0x188].copy_from_slice(&4_u32.to_le_bytes());
        image[0x188..0x18c].copy_from_slice(&3_u32.to_le_bytes());
        image[0x18c..0x190].copy_from_slice(b"GNU\0");
        image[0x190..0x194].copy_from_slice(&[1, 2, 3, 4]);
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&image).unwrap();
        file.flush().unwrap();
        let mut opened = File::open(file.path()).unwrap();
        assert_eq!(elf_rva_to_file_offset(&mut opened, 0x4010, 16).unwrap(), 0x110);
        assert!(elf_rva_to_file_offset(&mut opened, 0x4078, 16).is_err());
        assert_eq!(elf_gnu_build_id(file.path()).unwrap(), "01020304");
        // Reject a segment that claims bytes beyond the actual file.
        image[68..72].copy_from_slice(&0x1000_u32.to_le_bytes());
        fs::write(file.path(), &image).unwrap();
        assert!(elf_programs(&mut File::open(file.path()).unwrap()).is_err());
    }

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
        writer.start_file("lib/armeabi-v7a/libOriginal.so", SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)).unwrap();
        writer.write_all(b"original-native-library").unwrap();
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
        assert_eq!(archive.by_name("lib/armeabi-v7a/libOriginal.so").unwrap().compression(), CompressionMethod::Stored);
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
