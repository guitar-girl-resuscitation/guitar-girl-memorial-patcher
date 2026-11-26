//! Only ciphertext is shared between browsers. Keys are issued by redeeming a
//! normal download grant and never appear in a public URL or cacheable response.
use super::*;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use std::io::{Read, Seek, SeekFrom, Write};

const PART: usize = 16 * 1024 * 1024;
const PART_QUERY: &str = "ggfm-part=";
pub const PUBLIC_CACHE: &str = "public, max-age=31536000, immutable";
const CIPHER_TYPE: &str = "application/vnd.ggfm.encrypted-part";

fn hash_string(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn part_id(query: &str) -> Option<(&str, &str, u32)> {
    let value = query.strip_prefix(PART_QUERY)?;
    let (cache, rest) = value.split_once('.')?;
    let (generation, number) = rest.split_once('.')?;
    let index: u32 = number.parse().ok()?;
    (hash_string(cache) && hash_string(generation) && number == index.to_string())
        .then_some((cache, generation, index))
}

pub fn may_cache(uri: &axum::http::Uri, response: &Response) -> bool {
    uri.path() == "/" && uri.query().and_then(part_id).is_some()
        && response.status() == StatusCode::OK
        && response.headers().get(header::CONTENT_TYPE).is_some_and(|h| h == CIPHER_TYPE)
}

struct Artifact {
    key: [u8; 32],
    generation: String,
}

impl Artifact {
    fn open(path: &Path, create_key: bool) -> std::io::Result<Self> {
        // build_or_reuse has verified the completed file and its sidecar.
        let digest = fs::read_to_string(path.with_extension("sha256"))?;
        let digest = digest.trim().to_ascii_uppercase();
        if !hash_string(&digest) { return Err(std::io::Error::other("invalid output digest")); }
        let key_path = path.with_file_name(format!("{digest}.edge-key"));
        if create_key && !key_path.exists() {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|e| std::io::Error::other(e.to_string()))?;
            let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
            tmp.write_all(&key)?;
            tmp.as_file().sync_all()?;
            if let Err(error) = tmp.persist_noclobber(&key_path)
                && error.error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.error);
            }
        }
        let key: [u8; 32] = fs::read(key_path)?.try_into()
            .map_err(|_| std::io::Error::other("invalid edge key length"))?;
        let generation = hex::encode_upper(Sha256::digest(key));
        Ok(Self { key, generation })
    }
}

pub fn manifest(path: &Path, length: u64, version: u32) -> Result<Response, WebError> {
    let cache = path.file_stem().and_then(|s| s.to_str()).filter(|s| hash_string(s))
        .ok_or_else(|| internal("invalid artifact cache key"))?;
    let artifact = Artifact::open(path, true).map_err(internal)?;
    Ok(Json(serde_json::json!({
        "schema": 1, "cache": cache, "generation": artifact.generation,
        "key": hex::encode(artifact.key), "size": length, "partSize": PART, "versionCode": version
    })).into_response())
}

pub async fn part(root: PathBuf, query: &str) -> Result<Response, WebError> {
    let missing = || WebError(StatusCode::NOT_FOUND, "unknown artifact part".into());
    let (cache, generation, index) = part_id(query).ok_or_else(missing)?;
    let path = root.join(format!("{cache}.xapk"));
    let generation = generation.to_owned();
    static ENCRYPTIONS: Semaphore = Semaphore::const_new(2);
    let permit = ENCRYPTIONS.acquire().await.map_err(internal)?;
    let bytes = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let artifact = Artifact::open(&path, false).map_err(|_| missing())?;
        if artifact.generation != generation { return Err(missing()); }
        let mut file = fs::File::open(path).map_err(|_| missing())?;
        let offset = u64::from(index) * PART as u64;
        let size = file.metadata().map_err(internal)?.len();
        if offset >= size { return Err(missing()); }
        let mut bytes = vec![0; (size - offset).min(PART as u64) as usize];
        file.seek(SeekFrom::Start(offset)).map_err(internal)?;
        file.read_exact(&mut bytes).map_err(internal)?;
        let mut nonce = [0u8; 12];
        nonce[8..].copy_from_slice(&index.to_be_bytes());
        Aes256Gcm::new((&artifact.key).into())
            .encrypt_in_place(Nonce::from_slice(&nonce), &[], &mut bytes)
            .map_err(|_| internal("encrypting artifact part failed"))?;
        Ok::<_, WebError>(bytes)
    }).await.map_err(internal)??;
    Ok(([(header::CONTENT_TYPE, CIPHER_TYPE)], bytes).into_response())
}
