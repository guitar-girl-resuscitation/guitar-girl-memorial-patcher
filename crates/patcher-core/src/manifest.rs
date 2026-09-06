use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityManifest {
    pub schema: u32,
    pub source: Source,
    pub output: Output,
    #[serde(default)]
    pub il2cpp_hooks: Vec<Il2CppFingerprint>,
    #[serde(default)]
    pub il2cpp_dependencies: Vec<Il2CppFingerprint>,
    #[serde(default)]
    pub il2cpp_fields: BTreeMap<String, String>,
    #[serde(default)]
    pub fail_closed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    #[serde(default)]
    pub abi: AndroidAbi,
    pub version: String,
    pub xapk_sha256: String,
    pub splits: Vec<SplitDigest>,
    pub il2cpp: NativeDigest,
    pub global_metadata: FileDigest,
    pub master_bundle: FileDigest,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum AndroidAbi {
    #[default]
    #[serde(rename = "arm64-v8a")]
    Arm64,
    #[serde(rename = "armeabi-v7a")]
    ArmV7,
}

impl AndroidAbi {
    pub fn split_name(self) -> &'static str {
        match self { Self::Arm64 => "config.arm64_v8a.apk", Self::ArmV7 => "config.armeabi_v7a.apk" }
    }
    pub fn library(self, name: &str) -> String {
        let directory = match self { Self::Arm64 => "arm64-v8a", Self::ArmV7 => "armeabi-v7a" };
        format!("lib/{directory}/{name}")
    }
    pub fn elf_identity(self) -> (u8, u16) {
        match self { Self::Arm64 => (2, 183), Self::ArmV7 => (1, 40) }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDigest {
    pub sha256: String,
    pub build_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FileDigest {
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Il2CppFingerprint {
    pub name: String,
    pub rva: String,
    pub prologue: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SplitDigest {
    pub name: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub application_id: String,
    pub label: String,
}

impl CompatibilityManifest {
    pub fn parse(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}
