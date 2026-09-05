use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use ggfm_patcher_core::{
    ArtifactVersions, ChallengeError, ChallengeState, ChunkChallenge, ChunkProof,
    CompatibilityManifest, Limits, PatchArtifacts, PatchPlan, Pipeline, SigningConfig, Toolchain,
    sha256_file, verify_xapk,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, Semaphore},
};
use tokio_util::io::ReaderStream;

mod security;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    listen: String,
    compatibility_manifest: PathBuf,
    cache_root: PathBuf,
    work_root: PathBuf,
    tools: ToolConfig,
    artifacts: ArtifactConfig,
    signing: SigningConfigFile,
    versions: VersionConfig,
    prebuilt: Option<PrebuiltConfig>,
    application_id: Option<String>,
    #[serde(default)]
    security: security::SecurityConfig,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolConfig {
    java: PathBuf,
    apktool_jar: PathBuf,
    python: PathBuf,
    aapt2: PathBuf,
    zipalign: PathBuf,
    apksigner: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactConfig {
    patch_root: PathBuf,
    bootstrap_dex: PathBuf,
    bootstrap_dex_sha256: String,
    bootstrap_so: PathBuf,
    bootstrap_so_sha256: String,
    dobby_so: PathBuf,
    dobby_sha256: String,
    server_so: PathBuf,
    server_sha256: String,
    policy_manifest: PathBuf,
    policy_sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningConfigFile {
    keystore: PathBuf,
    alias: String,
    store_password_env: String,
    key_password_env: Option<String>,
    fingerprint: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionConfig {
    patch_commit: String,
    patch_version: String,
    server_version: String,
    server_abi: u32,
    #[serde(default)]
    revision: u32,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrebuiltConfig {
    operator_source_xapk: PathBuf,
}

struct PreparedSource {
    source: PathBuf,
    output: PathBuf,
    cache_key: String,
    source_len: u64,
    source_modified: SystemTime,
    output_len: u64,
    output_modified: SystemTime,
}

struct DownloadGrant {
    path: PathBuf,
    expires_at: i64,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    compatibility: Arc<CompatibilityManifest>,
    worker: Arc<Semaphore>,
    challenges: Arc<Mutex<BTreeMap<String, ChallengeState>>>,
    downloads: Arc<Mutex<BTreeMap<String, DownloadGrant>>>,
    prebuilt: Option<Arc<PreparedSource>>,
    deployment_fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Health {
    ok: bool,
    heavy_worker_limit: usize,
    prebuilt_enabled: bool,
    source_version: String,
    source_sha256: String,
    android_version: ggfm_patcher_core::AndroidVersion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchReady {
    cache_key: String,
    download_token: String,
    expires_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    source_sha256: String,
}

#[derive(Deserialize)]
struct ProofRequest {
    proof: ChunkProof,
}

#[derive(Debug)]
struct WebError(StatusCode, String);

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        if self.0.is_server_error() {
            tracing::error!(status = self.0.as_u16(), diagnostic = %self.1, "request failed internally");
            return (
                self.0,
                Json(serde_json::json!({"error": "service unavailable; retry later"})),
            )
                .into_response();
        }
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config_path = std::env::var_os("GGFM_PATCHER_CONFIG")
        .ok_or("GGFM_PATCHER_CONFIG must name the deployment configuration")?;
    let mut config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let version = ggfm_patcher_core::AndroidVersion::resolve(config.versions.revision)?;
    config.versions.revision = version.revision;
    tracing::info!(version_code = version.version_code, version_name = %version.version_name, "Android release identity resolved");
    validate_release_patch_checkout(&config)?;
    pipeline(&config).validate_artifacts()?;
    let compatibility = CompatibilityManifest::parse(&fs::read(&config.compatibility_manifest)?)?;
    fs::create_dir_all(&config.cache_root)?;
    fs::create_dir_all(&config.work_root)?;
    let address: SocketAddr = config.listen.parse()?;
    let security = security::Security::new(config.security.clone())?;
    security.validate_listen(address)?;
    let deployment_fingerprint = deployment_fingerprint(&config)?;
    let mut state = AppState {
        config: Arc::new(config),
        compatibility: Arc::new(compatibility),
        worker: Arc::new(Semaphore::new(1)),
        challenges: Arc::new(Mutex::new(BTreeMap::new())),
        downloads: Arc::new(Mutex::new(BTreeMap::new())),
        prebuilt: None,
        deployment_fingerprint,
    };
    state.prebuilt = prepare_operator_source(&state)?.map(Arc::new);
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/api/v1/patch", post(patch_upload))
        .route("/api/v1/prebuilt/challenge", post(issue_challenge))
        .route("/api/v1/prebuilt/prove", post(prove_challenge))
        .route("/api/v1/download/{token}", get(download))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            security,
            security::protect,
        ));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn validate_release_patch_checkout(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let expected = config.versions.patch_commit.trim();
    if expected.len() != 40
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || expected.bytes().all(|byte| byte == b'0')
    {
        return Err("web deployment requires a nonzero 40-hex Patch commit".into());
    }
    let head = Command::new("git")
        .args(["-C"])
        .arg(&config.artifacts.patch_root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !head.status.success()
        || !String::from_utf8_lossy(&head.stdout)
            .trim()
            .eq_ignore_ascii_case(expected)
    {
        return Err("Patch checkout does not match the configured commit".into());
    }
    let status = Command::new("git")
        .args(["-C"])
        .arg(&config.artifacts.patch_root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("Patch checkout is dirty or cannot be inspected".into());
    }
    Ok(())
}

fn deployment_fingerprint(config: &Config) -> Result<String, Box<dyn std::error::Error>> {
    // Moving tags such as nightly are labels, never immutable cache identity.
    let provenance = serde_json::to_vec(&serde_json::json!({
        "artifacts": config.artifacts,
        "versions": config.versions,
        "applicationId": config.application_id,
        "signer": config.signing.fingerprint,
        "patcher": sha256_file(&std::env::current_exe()?)?,
        "apktool": sha256_file(&config.tools.apktool_jar)?,
        "manifest": sha256_file(&config.compatibility_manifest)?,
    }))?;
    Ok(hex::encode_upper(Sha256::digest(provenance)))
}

fn prepare_operator_source(
    state: &AppState,
) -> Result<Option<PreparedSource>, Box<dyn std::error::Error>> {
    let Some(config) = &state.config.prebuilt else {
        return Ok(None);
    };
    let source = &config.operator_source_xapk;
    if !source.is_file() {
        tracing::info!("operator source absent; complete verified uploads required");
        return Ok(None);
    }
    if let Err(error) = verify_xapk(source, &state.compatibility, Limits::default()) {
        tracing::warn!(%error, "operator source rejected; complete verified uploads required");
        return Ok(None);
    }
    tracing::info!("preparing verified operator package once before serving requests");
    let (cache_key, output) = build_or_reuse(
        state,
        source,
        state.config.application_id.as_deref(),
        state.config.versions.revision,
    )?;
    let source_meta = fs::metadata(source)?;
    let output_meta = fs::metadata(&output)?;
    Ok(Some(PreparedSource {
        source: source.clone(),
        output,
        cache_key,
        source_len: source_meta.len(),
        source_modified: source_meta.modified()?,
        output_len: output_meta.len(),
        output_modified: output_meta.modified()?,
    }))
}

fn verify_prepared_metadata(prebuilt: &PreparedSource) -> Result<(), WebError> {
    for (path, length, modified) in [
        (
            &prebuilt.source,
            prebuilt.source_len,
            prebuilt.source_modified,
        ),
        (
            &prebuilt.output,
            prebuilt.output_len,
            prebuilt.output_modified,
        ),
    ] {
        let meta = fs::metadata(path).map_err(|_| {
            WebError(
                StatusCode::SERVICE_UNAVAILABLE,
                "prepared file unavailable; restart the deployment to revalidate".into(),
            )
        })?;
        if meta.len() != length || meta.modified().ok() != Some(modified) {
            return Err(WebError(
                StatusCode::SERVICE_UNAVAILABLE,
                "prepared file changed; restart the deployment to revalidate".into(),
            ));
        }
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        ok: true,
        heavy_worker_limit: 1,
        prebuilt_enabled: state.prebuilt.is_some(),
        source_version: state.compatibility.source.version.clone(),
        source_sha256: state.compatibility.source.xapk_sha256.clone(),
        android_version: ggfm_patcher_core::AndroidVersion::resolve(state.config.versions.revision)
            .expect("version validated before serving"),
    })
}

async fn index() -> Response {
    (
        [
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(include_str!("../../../web/index.html")),
    )
        .into_response()
}

async fn patch_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<PatchReady>, WebError> {
    if state.prebuilt.is_some() {
        return Err(WebError(
            StatusCode::CONFLICT,
            "use the possession challenge for the prepared package".into(),
        ));
    }
    let permit = state.worker.clone().try_acquire_owned().map_err(|_| {
        WebError(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker busy; retry later".into(),
        )
    })?;
    let requested_id = optional_header(&headers, "x-ggfm-application-id")?;
    if requested_id.is_some() && requested_id != state.config.application_id {
        return Err(WebError(
            StatusCode::BAD_REQUEST,
            "application ID is fixed by the deployment".into(),
        ));
    }
    let application_id = state.config.application_id.clone();
    let temp = tempfile::Builder::new()
        .prefix("ggfm-upload-")
        .tempdir_in(&state.config.work_root)
        .map_err(internal)?;
    let source = temp.path().join("source.xapk");
    tokio::time::timeout(
        Duration::from_secs(600),
        stream_request_body(
            request.into_body(),
            &source,
            Limits::default().max_xapk_bytes,
        ),
    )
    .await
    .map_err(|_| WebError(StatusCode::REQUEST_TIMEOUT, "upload timed out".into()))??;

    let state_for_job = state.clone();
    let source_for_job = source.clone();
    let result = tokio::task::spawn_blocking(move || {
        // These owners must survive cancellation of the HTTP request future.
        // Never allow a disconnected client to release the heavy-worker slot
        // or remove a source still being read by the blocking pipeline.
        let _permit = permit;
        let _upload = temp;
        verify_xapk(
            &source_for_job,
            &state_for_job.compatibility,
            Limits::default(),
        )
        .map_err(|_| {
            WebError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported or invalid XAPK".into(),
            )
        })?;
        build_or_reuse(
            &state_for_job,
            &source_for_job,
            application_id.as_deref(),
            state_for_job.config.versions.revision,
        )
        .map_err(internal)
    })
    .await
    .map_err(internal)??;
    grant_download(&state, result.0, result.1).await
}

async fn issue_challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChunkChallenge>, WebError> {
    let prebuilt = state.prebuilt.as_ref().ok_or_else(|| {
        WebError(
            StatusCode::NOT_FOUND,
            "prebuilt distribution is disabled".into(),
        )
    })?;
    if !request
        .source_sha256
        .eq_ignore_ascii_case(&state.compatibility.source.xapk_sha256)
    {
        return Err(WebError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported source hash".into(),
        ));
    }
    verify_prepared_metadata(prebuilt)?;
    let mut challenges = state.challenges.lock().await;
    challenges.retain(|_, challenge| challenge.expires_at() >= unix_now());
    if challenges.len() >= 128 {
        return Err(WebError(
            StatusCode::TOO_MANY_REQUESTS,
            "challenge capacity reached; retry later".into(),
        ));
    }
    let (challenge_state, challenge) =
        ChallengeState::issue(&prebuilt.source, 64 * 1024, 8, unix_now(), 180)
            .map_err(|error| WebError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    challenges.insert(challenge.nonce.clone(), challenge_state);
    Ok(Json(challenge))
}

async fn prove_challenge(
    State(state): State<AppState>,
    Json(request): Json<ProofRequest>,
) -> Result<Json<PatchReady>, WebError> {
    let prebuilt = state.prebuilt.as_ref().ok_or_else(|| {
        WebError(
            StatusCode::NOT_FOUND,
            "prebuilt distribution is disabled".into(),
        )
    })?;
    let challenge = state
        .challenges
        .lock()
        .await
        .remove(&request.proof.nonce)
        .ok_or_else(|| {
            WebError(
                StatusCode::BAD_REQUEST,
                "unknown or consumed challenge".into(),
            )
        })?;
    challenge
        .verify(&request.proof, unix_now())
        .map_err(proof_error)?;
    verify_prepared_metadata(prebuilt)?;
    grant_download(&state, prebuilt.cache_key.clone(), prebuilt.output.clone()).await
}

fn proof_error(error: ChallengeError) -> WebError {
    let status = match error {
        ChallengeError::Expired => StatusCode::GONE,
        _ => StatusCode::UNAUTHORIZED,
    };
    WebError(status, error.to_string())
}

async fn download(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
) -> Result<Response, WebError> {
    let grant = state.downloads.lock().await.remove(&token).ok_or_else(|| {
        WebError(
            StatusCode::NOT_FOUND,
            "unknown or consumed download token".into(),
        )
    })?;
    if unix_now() > grant.expires_at || !grant.path.is_file() {
        return Err(WebError(StatusCode::GONE, "download grant expired".into()));
    }
    if let Some(prebuilt) = &state.prebuilt {
        verify_prepared_metadata(prebuilt)?;
    }
    let file = tokio::fs::File::open(grant.path).await.map_err(internal)?;
    let length = file.metadata().await.map_err(internal)?.len();
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=Guitar-Girl-Fan-Memorial-Build.xapk",
            ),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response();
    // A stream timeout/disconnect must be detected as an incomplete download,
    // never a successfully completed (but truncated) XAPK.
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        length.to_string().parse().map_err(internal)?,
    );
    Ok(response)
}

fn build_or_reuse(
    state: &AppState,
    source: &Path,
    application_id: Option<&str>,
    revision: u32,
) -> Result<(String, PathBuf), String> {
    let verified = verify_xapk(source, &state.compatibility, Limits::default())
        .map_err(|error| error.to_string())?;
    let versions = ArtifactVersions {
        patch_commit: state.config.versions.patch_commit.clone(),
        patch_version: state.config.versions.patch_version.clone(),
        server_version: state.config.versions.server_version.clone(),
        server_sha256: state.config.artifacts.server_sha256.clone(),
        server_abi: state.config.versions.server_abi,
        signer_fingerprint: state.config.signing.fingerprint.clone(),
    };
    let mut plan = PatchPlan::create(&verified, &state.compatibility, &versions, application_id)
        .map_err(|error| error.to_string())?;
    plan.cache_key = hex::encode_upper(Sha256::digest(
        format!(
            "{}\0{}\0{}",
            plan.cache_key, state.deployment_fingerprint, revision
        )
        .as_bytes(),
    ));
    let output = state
        .config
        .cache_root
        .join(format!("{}.xapk", plan.cache_key));
    let checksum = state
        .config
        .cache_root
        .join(format!("{}.sha256", plan.cache_key));
    if output.exists() {
        let expected = fs::read_to_string(&checksum)
            .map_err(|_| "cached XAPK has no verified SHA-256 sidecar".to_owned())?;
        let actual = sha256_file(&output).map_err(|error| error.to_string())?;
        if !actual.eq_ignore_ascii_case(expected.trim()) {
            return Err("cached XAPK failed its SHA-256 sidecar check".into());
        }
    } else {
        pipeline(&state.config)
            .run(
                source,
                &state.compatibility,
                &verified,
                &plan,
                &output,
                revision,
            )
            .map_err(|error| error.to_string())?;
        let digest = sha256_file(&output).map_err(|error| error.to_string())?;
        write_checksum_noclobber(&checksum, &digest)?;
    }
    Ok((plan.cache_key, output))
}

fn write_checksum_noclobber(path: &Path, digest: &str) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().ok_or("checksum path has no parent")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    temporary
        .write_all(digest.as_bytes())
        .and_then(|_| temporary.as_file_mut().sync_all())
        .map_err(|error| error.to_string())?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error.to_string())?;
    Ok(())
}

fn pipeline(config: &Config) -> Pipeline {
    Pipeline {
        tools: Toolchain {
            java: config.tools.java.clone(),
            apktool_jar: config.tools.apktool_jar.clone(),
            python: config.tools.python.clone(),
            aapt2: config.tools.aapt2.clone(),
            zipalign: config.tools.zipalign.clone(),
            apksigner: config.tools.apksigner.clone(),
        },
        artifacts: PatchArtifacts {
            patch_root: config.artifacts.patch_root.clone(),
            bootstrap_dex: config.artifacts.bootstrap_dex.clone(),
            bootstrap_dex_sha256: config.artifacts.bootstrap_dex_sha256.clone(),
            bootstrap_so: config.artifacts.bootstrap_so.clone(),
            bootstrap_so_sha256: config.artifacts.bootstrap_so_sha256.clone(),
            dobby_so: config.artifacts.dobby_so.clone(),
            dobby_sha256: config.artifacts.dobby_sha256.clone(),
            server_so: config.artifacts.server_so.clone(),
            server_sha256: config.artifacts.server_sha256.clone(),
            policy_manifest: config.artifacts.policy_manifest.clone(),
            policy_sha256: config.artifacts.policy_sha256.clone(),
        },
        signing: SigningConfig {
            keystore: config.signing.keystore.clone(),
            alias: config.signing.alias.clone(),
            store_password_env: config.signing.store_password_env.clone(),
            key_password_env: config.signing.key_password_env.clone(),
        },
        work_root: config.work_root.clone(),
        limits: Limits::default(),
    }
}

async fn stream_request_body(body: Body, output: &Path, maximum: u64) -> Result<(), WebError> {
    let mut output = tokio::fs::File::create(output).await.map_err(internal)?;
    let mut stream = body.into_data_stream();
    let mut total = 0_u64;
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .map_err(|_| WebError(StatusCode::REQUEST_TIMEOUT, "upload stalled".into()))?
    {
        let chunk = chunk.map_err(|error| WebError(StatusCode::BAD_REQUEST, error.to_string()))?;
        total = total.saturating_add(chunk.len() as u64);
        if total > maximum {
            return Err(WebError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "XAPK exceeds upload limit".into(),
            ));
        }
        output.write_all(&chunk).await.map_err(internal)?;
    }
    output.flush().await.map_err(internal)?;
    Ok(())
}

async fn grant_download(
    state: &AppState,
    cache_key: String,
    path: PathBuf,
) -> Result<Json<PatchReady>, WebError> {
    let token = random_token()?;
    let expires_at = unix_now() + 600;
    let mut downloads = state.downloads.lock().await;
    downloads.retain(|_, grant| grant.expires_at >= unix_now());
    if downloads.len() >= 256 {
        return Err(WebError(
            StatusCode::TOO_MANY_REQUESTS,
            "download capacity reached; retry later".into(),
        ));
    }
    downloads.insert(token.clone(), DownloadGrant { path, expires_at });
    Ok(Json(PatchReady {
        cache_key,
        download_token: token,
        expires_at,
    }))
}

fn optional_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, WebError> {
    headers
        .get(name)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| WebError(StatusCode::BAD_REQUEST, format!("invalid {name} header")))
}

fn random_token() -> Result<String, WebError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| {
        WebError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "randomness unavailable".into(),
        )
    })?;
    Ok(hex::encode(bytes))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn internal(error: impl std::fmt::Display) -> WebError {
    WebError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_proof_expiry_is_not_an_authentication_failure() {
        assert_eq!(proof_error(ChallengeError::Expired).0, StatusCode::GONE);
        assert_eq!(
            proof_error(ChallengeError::ProofMismatch).0,
            StatusCode::UNAUTHORIZED
        );
    }

    fn test_state(dir: &Path) -> AppState {
        let mut config: Config =
            serde_json::from_str(include_str!("../../../config/patcher.example.json")).unwrap();
        config.work_root = dir.join("work");
        config.cache_root = dir.join("cache");
        config.prebuilt = None;
        config.versions.revision = ggfm_patcher_core::AndroidVersion::resolve(0)
            .or_else(|_| ggfm_patcher_core::AndroidVersion::resolve(1))
            .unwrap()
            .revision;
        fs::create_dir_all(&config.work_root).unwrap();
        fs::create_dir_all(&config.cache_root).unwrap();
        AppState {
            config: Arc::new(config),
            compatibility: Arc::new(
                CompatibilityManifest::parse(include_bytes!(
                    "../../../patch/compatibility/8.0.0.json"
                ))
                .unwrap(),
            ),
            worker: Arc::new(Semaphore::new(1)),
            challenges: Arc::new(Mutex::new(BTreeMap::new())),
            downloads: Arc::new(Mutex::new(BTreeMap::new())),
            prebuilt: None,
            deployment_fingerprint: "synthetic-test".into(),
        }
    }

    #[tokio::test]
    async fn absent_invalid_operator_falls_back_and_upload_is_verified_and_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        assert!(prepare_operator_source(&state).unwrap().is_none());
        let source = dir.path().join("operator-source");
        Arc::make_mut(&mut state.config).prebuilt = Some(PrebuiltConfig {
            operator_source_xapk: source.clone(),
        });
        assert!(prepare_operator_source(&state).unwrap().is_none());
        fs::write(&source, b"not a supported package").unwrap();
        assert!(prepare_operator_source(&state).unwrap().is_none());
        let Json(health) = health(State(state.clone())).await;
        assert!(!health.prebuilt_enabled);
        assert_eq!(health.heavy_worker_limit, 1);
        let request = Request::new(Body::from("incorrect source hash"));
        let error = patch_upload(State(state.clone()), HeaderMap::new(), request)
            .await
            .err()
            .unwrap();
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(state.worker.available_permits(), 1);
        assert_eq!(fs::read_dir(&state.config.work_root).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&state.config.cache_root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn prepared_proof_download_is_single_use_and_never_takes_build_permit() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        let source = dir.path().join("synthetic-source");
        let output = dir.path().join("synthetic-result");
        let bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        fs::write(&source, &bytes).unwrap();
        fs::write(&output, b"cached synthetic result").unwrap();
        state.prebuilt = Some(Arc::new(PreparedSource {
            source: source.clone(),
            output: output.clone(),
            cache_key: "cache-test".into(),
            source_len: bytes.len() as u64,
            source_modified: fs::metadata(source).unwrap().modified().unwrap(),
            output_len: fs::metadata(&output).unwrap().len(),
            output_modified: fs::metadata(output).unwrap().modified().unwrap(),
        }));
        let _busy = state.worker.clone().try_acquire_owned().unwrap();
        let Json(challenge) = issue_challenge(
            State(state.clone()),
            Json(ChallengeRequest {
                source_sha256: state.compatibility.source.xapk_sha256.clone(),
            }),
        )
        .await
        .unwrap();
        let proof = ChunkProof {
            nonce: challenge.nonce,
            chunks_base64: challenge
                .offsets
                .iter()
                .map(|offset| {
                    let start = *offset as usize;
                    STANDARD.encode(&bytes[start..start + challenge.chunk_size as usize])
                })
                .collect(),
        };
        let Json(ready) = prove_challenge(
            State(state.clone()),
            Json(ProofRequest {
                proof: proof.clone(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(ready.cache_key, "cache-test");
        assert!(
            prove_challenge(State(state.clone()), Json(ProofRequest { proof }))
                .await
                .is_err()
        );
        let response = download(State(state.clone()), AxumPath(ready.download_token.clone()))
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "23");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .as_ref(),
            b"cached synthetic result"
        );
        assert!(
            download(State(state.clone()), AxumPath(ready.download_token))
                .await
                .is_err()
        );
        assert_eq!(state.worker.available_permits(), 0);
        let error = patch_upload(State(state), HeaderMap::new(), Request::new(Body::empty()))
            .await
            .err()
            .unwrap();
        assert_eq!(error.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn disconnected_request_cannot_release_a_running_worker() {
        let worker = Arc::new(Semaphore::new(1));
        let permit = worker.clone().try_acquire_owned().unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let (finished, done) = tokio::sync::oneshot::channel();
        let job = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(_permit);
            let _ = finished.send(());
        });
        drop(job); // exactly what cancellation of an awaiting HTTP future does
        assert!(worker.clone().try_acquire_owned().is_err());
        release.send(()).unwrap();
        done.await.unwrap();
        assert!(worker.try_acquire_owned().is_ok());
    }

    #[test]
    fn replaced_prepared_files_require_revalidation() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let output = dir.path().join("output");
        fs::write(&source, b"synthetic source").unwrap();
        fs::write(&output, b"synthetic output").unwrap();
        let sm = fs::metadata(&source).unwrap();
        let om = fs::metadata(&output).unwrap();
        let prepared = PreparedSource {
            source,
            output: output.clone(),
            cache_key: "test".into(),
            source_len: sm.len(),
            source_modified: sm.modified().unwrap(),
            output_len: om.len(),
            output_modified: om.modified().unwrap(),
        };
        assert!(verify_prepared_metadata(&prepared).is_ok());
        fs::write(output, b"replaced").unwrap();
        assert!(verify_prepared_metadata(&prepared).is_err());
    }
}
