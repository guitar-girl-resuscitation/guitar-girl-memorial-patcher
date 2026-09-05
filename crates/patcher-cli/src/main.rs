use std::{fs, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use ggfm_patcher_core::{
    ArtifactVersions, CompatibilityManifest, Limits, PatchArtifacts, PatchPlan, Pipeline,
    SigningConfig, Toolchain, sha256_file, verify_xapk,
};

#[derive(Parser)]
#[command(
    name = "ggfm-patcher",
    about = "Fail-closed Guitar Girl memorial package tool"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the immutable Android version embedded in this release (JSON).
    Version,
    Hash {
        path: PathBuf,
    },
    Verify {
        xapk: PathBuf,
        manifest: PathBuf,
    },
    Plan {
        xapk: PathBuf,
        manifest: PathBuf,
        #[arg(long)]
        patch_commit: String,
        #[arg(long)]
        patch_version: String,
        #[arg(long)]
        server_version: String,
        #[arg(long)]
        server_sha256: String,
        #[arg(long)]
        signer_fingerprint: String,
        #[arg(long)]
        application_id: Option<String>,
    },
    Patch(Box<PatchArguments>),
}

#[derive(Args)]
struct PatchArguments {
    xapk: PathBuf,
    manifest: PathBuf,
    output: PathBuf,
    #[arg(long)]
    patch_root: PathBuf,
    #[arg(long)]
    bootstrap_dex: PathBuf,
    #[arg(long)]
    bootstrap_dex_sha256: String,
    #[arg(long)]
    bootstrap_so: PathBuf,
    #[arg(long)]
    bootstrap_so_sha256: String,
    #[arg(long)]
    dobby_so: PathBuf,
    #[arg(long)]
    dobby_sha256: String,
    #[arg(long)]
    server_so: PathBuf,
    #[arg(long)]
    policy_manifest: PathBuf,
    #[arg(long)]
    policy_sha256: String,
    #[arg(long)]
    java: PathBuf,
    #[arg(long)]
    apktool_jar: PathBuf,
    #[arg(long)]
    python: PathBuf,
    #[arg(long)]
    aapt2: PathBuf,
    #[arg(long)]
    zipalign: PathBuf,
    #[arg(long)]
    apksigner: PathBuf,
    #[arg(long)]
    keystore: PathBuf,
    #[arg(long)]
    key_alias: String,
    #[arg(long, default_value = "GGFM_KEYSTORE_PASSWORD")]
    store_password_env: String,
    #[arg(long)]
    key_password_env: Option<String>,
    #[arg(long)]
    work_root: PathBuf,
    #[arg(long)]
    patch_commit: String,
    #[arg(long)]
    patch_version: String,
    #[arg(long)]
    server_version: String,
    #[arg(long)]
    server_sha256: String,
    #[arg(long)]
    signer_fingerprint: String,
    #[arg(long)]
    application_id: Option<String>,
    /// Zero uses the compiled release; explicit values are for unnumbered local builds.
    #[arg(long, default_value_t = 0)]
    revision: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::Version => println!(
            "{}",
            serde_json::to_string(&ggfm_patcher_core::AndroidVersion::resolve(0)?)?
        ),
        Command::Hash { path } => println!("{}", sha256_file(&path)?),
        Command::Verify { xapk, manifest } => {
            let manifest = load_manifest(&manifest)?;
            let verified = verify_xapk(&xapk, &manifest, Limits::default())?;
            println!("{} {}", verified.source_version, verified.outer_sha256);
        }
        Command::Plan {
            xapk,
            manifest,
            patch_commit,
            patch_version,
            server_version,
            server_sha256,
            signer_fingerprint,
            application_id,
        } => {
            let manifest = load_manifest(&manifest)?;
            let verified = verify_xapk(&xapk, &manifest, Limits::default())?;
            let plan = PatchPlan::create(
                &verified,
                &manifest,
                &ArtifactVersions {
                    patch_commit,
                    patch_version,
                    server_version,
                    server_sha256,
                    server_abi: 1,
                    signer_fingerprint,
                },
                application_id.as_deref(),
            )?;
            println!("applicationId={}", plan.application_id);
            println!("cacheKey={}", plan.cache_key);
            for stage in plan.stages {
                println!("- {stage}");
            }
        }
        Command::Patch(arguments) => {
            let PatchArguments {
                xapk,
                manifest,
                output,
                patch_root,
                bootstrap_dex,
                bootstrap_dex_sha256,
                bootstrap_so,
                bootstrap_so_sha256,
                dobby_so,
                dobby_sha256,
                server_so,
                policy_manifest,
                policy_sha256,
                java,
                apktool_jar,
                python,
                aapt2,
                zipalign,
                apksigner,
                keystore,
                key_alias,
                store_password_env,
                key_password_env,
                work_root,
                patch_commit,
                patch_version,
                server_version,
                server_sha256,
                signer_fingerprint,
                application_id,
                revision,
            } = *arguments;
            let compatibility = load_manifest(&manifest)?;
            let verified = verify_xapk(&xapk, &compatibility, Limits::default())?;
            let plan = PatchPlan::create(
                &verified,
                &compatibility,
                &ArtifactVersions {
                    patch_commit,
                    patch_version,
                    server_version,
                    server_sha256: server_sha256.clone(),
                    server_abi: 1,
                    signer_fingerprint,
                },
                application_id.as_deref(),
            )?;
            let pipeline = Pipeline {
                tools: Toolchain {
                    java,
                    apktool_jar,
                    python,
                    aapt2,
                    zipalign,
                    apksigner,
                },
                artifacts: PatchArtifacts {
                    patch_root,
                    bootstrap_dex,
                    bootstrap_dex_sha256,
                    bootstrap_so,
                    bootstrap_so_sha256,
                    dobby_so,
                    dobby_sha256,
                    server_so,
                    server_sha256,
                    policy_manifest,
                    policy_sha256,
                },
                signing: SigningConfig {
                    keystore,
                    alias: key_alias,
                    store_password_env,
                    key_password_env,
                },
                work_root,
                limits: Limits::default(),
            };
            pipeline.run(&xapk, &compatibility, &verified, &plan, &output, revision)?;
            println!("{}", output.display());
        }
    }
    Ok(())
}

fn load_manifest(path: &PathBuf) -> Result<CompatibilityManifest, Box<dyn std::error::Error>> {
    Ok(CompatibilityManifest::parse(&fs::read(path)?)?)
}
