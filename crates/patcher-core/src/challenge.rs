use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkChallenge {
    pub nonce: String,
    pub source_size: u64,
    pub chunk_size: u32,
    pub offsets: Vec<u64>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkProof {
    pub nonce: String,
    pub chunks_base64: Vec<String>,
}

pub struct ChallengeState {
    challenge: ChunkChallenge,
    digests: Vec<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("source is too small for a possession challenge")]
    SourceTooSmall,
    #[error("invalid challenge parameters")]
    InvalidParameters,
    #[error("secure randomness is unavailable")]
    Random,
    #[error("challenge expired")]
    Expired,
    #[error("challenge nonce mismatch")]
    NonceMismatch,
    #[error("wrong number of chunks")]
    ChunkCount,
    #[error("chunk encoding is invalid")]
    Encoding,
    #[error("chunk length is invalid")]
    ChunkLength,
    #[error("chunk proof does not match the operator source")]
    ProofMismatch,
}

impl ChallengeState {
    pub fn expires_at(&self) -> i64 {
        self.challenge.expires_at
    }
    pub fn issue(
        source: &Path,
        chunk_size: u32,
        chunk_count: usize,
        now: i64,
        ttl_seconds: i64,
    ) -> Result<(Self, ChunkChallenge), ChallengeError> {
        if !(4096..=1024 * 1024).contains(&chunk_size)
            || !(2..=16).contains(&chunk_count)
            || !(30..=600).contains(&ttl_seconds)
        {
            return Err(ChallengeError::InvalidParameters);
        }
        let mut file = File::open(source)?;
        let source_size = file.metadata()?.len();
        if source_size < u64::from(chunk_size) * 2 {
            return Err(ChallengeError::SourceTooSmall);
        }
        let max_offset = source_size - u64::from(chunk_size);
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ChallengeError::Random)?;
        let mut offsets = Vec::with_capacity(chunk_count);
        let mut digests = Vec::with_capacity(chunk_count);
        let mut buffer = vec![0_u8; chunk_size as usize];
        for index in 0..chunk_count {
            let mut seed = Sha256::new();
            seed.update(nonce);
            seed.update((index as u64).to_be_bytes());
            let raw: [u8; 8] = seed.finalize()[..8].try_into().unwrap();
            let offset = u64::from_be_bytes(raw) % (max_offset + 1);
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buffer)?;
            offsets.push(offset);
            digests.push(Sha256::digest(&buffer).into());
        }
        let challenge = ChunkChallenge {
            nonce: hex::encode_upper(nonce),
            source_size,
            chunk_size,
            offsets,
            expires_at: now.saturating_add(ttl_seconds),
        };
        Ok((
            Self {
                challenge: challenge.clone(),
                digests,
            },
            challenge,
        ))
    }

    pub fn verify(self, proof: &ChunkProof, now: i64) -> Result<(), ChallengeError> {
        if now > self.challenge.expires_at {
            return Err(ChallengeError::Expired);
        }
        if proof.nonce != self.challenge.nonce {
            return Err(ChallengeError::NonceMismatch);
        }
        if proof.chunks_base64.len() != self.digests.len() {
            return Err(ChallengeError::ChunkCount);
        }
        for (encoded, expected) in proof.chunks_base64.iter().zip(self.digests) {
            let chunk = STANDARD
                .decode(encoded)
                .map_err(|_| ChallengeError::Encoding)?;
            if chunk.len() != self.challenge.chunk_size as usize {
                return Err(ChallengeError::ChunkLength);
            }
            let actual: [u8; 32] = Sha256::digest(chunk).into();
            if !constant_time_equal(&actual, &expected) {
                return Err(ChallengeError::ProofMismatch);
            }
        }
        Ok(())
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn source_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes: Vec<u8> = (0..32_768).map(|index| (index % 251) as u8).collect();
        fs::write(file.path(), bytes).unwrap();
        file
    }

    fn proof_for(source: &Path, challenge: &ChunkChallenge) -> ChunkProof {
        let mut file = File::open(source).unwrap();
        let mut chunks = Vec::with_capacity(challenge.offsets.len());
        for offset in &challenge.offsets {
            file.seek(SeekFrom::Start(*offset)).unwrap();
            let mut bytes = vec![0_u8; challenge.chunk_size as usize];
            file.read_exact(&mut bytes).unwrap();
            chunks.push(STANDARD.encode(bytes));
        }
        ChunkProof {
            nonce: challenge.nonce.clone(),
            chunks_base64: chunks,
        }
    }

    #[test]
    fn valid_chunk_proof_is_accepted() {
        let source = source_file();
        let (state, challenge) = ChallengeState::issue(source.path(), 4096, 4, 1_000, 60).unwrap();
        state
            .verify(&proof_for(source.path(), &challenge), 1_060)
            .unwrap();
    }

    #[test]
    fn wrong_chunk_and_expired_proofs_are_rejected() {
        let source = source_file();
        let (state, challenge) = ChallengeState::issue(source.path(), 4096, 4, 1_000, 60).unwrap();
        let mut proof = proof_for(source.path(), &challenge);
        proof.chunks_base64[0] = STANDARD.encode(vec![0_u8; 4096]);
        assert!(matches!(
            state.verify(&proof, 1_001),
            Err(ChallengeError::ProofMismatch)
        ));

        let (state, challenge) = ChallengeState::issue(source.path(), 4096, 4, 1_000, 60).unwrap();
        assert!(matches!(
            state.verify(&proof_for(source.path(), &challenge), 1_061),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn challenge_parameters_and_nonce_are_fail_closed() {
        let source = source_file();
        assert!(matches!(
            ChallengeState::issue(source.path(), 1024, 4, 1_000, 60),
            Err(ChallengeError::InvalidParameters)
        ));
        let (state, challenge) = ChallengeState::issue(source.path(), 4096, 2, 1_000, 60).unwrap();
        let mut proof = proof_for(source.path(), &challenge);
        proof.nonce.push('0');
        assert!(matches!(
            state.verify(&proof, 1_001),
            Err(ChallengeError::NonceMismatch)
        ));
    }

    #[test]
    fn source_must_hold_at_least_two_full_chunks() {
        let source = tempfile::NamedTempFile::new().unwrap();
        fs::write(source.path(), vec![0_u8; 8_191]).unwrap();
        assert!(matches!(
            ChallengeState::issue(source.path(), 4096, 2, 1_000, 60),
            Err(ChallengeError::SourceTooSmall)
        ));
    }
}
