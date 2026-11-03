use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, KEY_LEN};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct VaultEntry {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub color: String,
    #[serde(rename = "customFields", default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(rename = "totpSecret", default)]
    pub totp_secret: String,
    #[serde(default)]
    pub starred: bool,
    #[serde(rename = "lastModified", default)]
    pub last_modified: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct WalletField {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(rename = "isSecret", default)]
    pub is_secret: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct Wallet {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type", default)]
    pub wallet_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub fields: Vec<WalletField>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SectionConfig {
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub starred: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SectionSettings {
    #[serde(default)]
    pub theme: Option<serde_json::Value>,
    #[serde(rename = "customFont", default)]
    pub custom_font: Option<String>,
    #[serde(rename = "autoLockTime", default)]
    pub auto_lock_time: Option<u64>,
    #[serde(flatten)]
    pub sections: HashMap<String, SectionConfig>,
}

impl Zeroize for SectionSettings {
    fn zeroize(&mut self) {
        if let Some(mut font) = self.custom_font.take() {
            font.zeroize();
        }
        self.sections.clear();
    }
}

impl Drop for SectionSettings {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SectionSettings {}

fn map_or_legacy_array<'de, D, V>(d: D) -> Result<HashMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: DeserializeOwned,
{
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Object(m) => m
            .into_iter()
            .map(|(k, v)| serde_json::from_value(v).map(|val| (k, val)).map_err(serde::de::Error::custom))
            .collect(),
        serde_json::Value::Array(_) | serde_json::Value::Null => Ok(HashMap::new()),
        other => Err(serde::de::Error::custom(format!(
            "expected map, array, or null, got {other}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VaultPayload {
    #[serde(deserialize_with = "map_or_legacy_array", default)]
    pub vault: HashMap<String, VaultEntry>,
    #[serde(default)]
    pub backups: HashMap<String, Vec<String>>,
    #[serde(rename = "sectionSettings", default)]
    pub section_settings: SectionSettings,
    #[serde(default)]
    pub wallets: Vec<Wallet>,
}

impl Zeroize for VaultPayload {
    fn zeroize(&mut self) {
        for (_, mut entry) in self.vault.drain() {
            entry.zeroize();
        }
        for (_, mut codes) in self.backups.drain() {
            for mut code in codes.drain(..) {
                code.zeroize();
            }
        }
        self.wallets.zeroize();
        self.section_settings.zeroize();
    }
}

impl Drop for VaultPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VaultPayload {}

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Crypto(crypto::CryptoError),
    Json(serde_json::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "vault I/O error: {e}"),
            Self::Crypto(e) => write!(f, "vault crypto error: {e}"),
            Self::Json(e) => write!(f, "vault JSON error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Json(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<crypto::CryptoError> for VaultError {
    fn from(e: crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub async fn load_vault(path: &Path, key: &[u8]) -> Result<VaultPayload, VaultError> {
    debug_assert_eq!(key.len(), KEY_LEN);
    let raw = tokio::fs::read(path).await?;
    let plain = crypto::decrypt_vault_data(key, &raw)?;
    if serde_json::from_slice::<Vec<serde_json::Value>>(&plain).is_ok() {
        return Ok(VaultPayload::default());
    }
    Ok(serde_json::from_slice(&plain)?)
}

pub async fn load_vault_with_password(
    path: &Path,
    password: &str,
    salt: &[u8],
) -> Result<(VaultPayload, Zeroizing<[u8; KEY_LEN]>, bool), VaultError> {
    let raw = tokio::fs::read(path).await?;
    let (plain, key, upgraded) = crypto::decrypt_vault_dual_kdf(password.as_bytes(), salt, &raw)?;
    if serde_json::from_slice::<Vec<serde_json::Value>>(&plain).is_ok() {
        return Ok((VaultPayload::default(), key, upgraded));
    }
    let payload: VaultPayload = serde_json::from_slice(&plain)?;
    Ok((payload, key, upgraded))
}

pub async fn save_vault(path: &Path, key: &[u8], payload: &VaultPayload) -> Result<(), VaultError> {
    use tokio::io::AsyncWriteExt;

    debug_assert_eq!(key.len(), KEY_LEN);
    let json = serde_json::to_vec(payload)?;
    let enc = crypto::encrypt_vault_data(key, &json)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    let tmp_path = match path.file_name() {
        Some(name) => {
            let mut tmp_name = name.to_os_string();
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => path.with_extension("tmp"),
    };

    let mut file = tokio::fs::File::create(&tmp_path).await?;
    file.write_all(&enc).await?;
    file.sync_all().await?;
    drop(file);

    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

pub fn user_data_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(base) = directories::BaseDirs::new().map(|b| b.config_dir().to_path_buf()) {
        for name in [
            "norythmpasswd",
            "NorythmPasswd",
            "masterpasswd",
            "MasterPasswd",
            "master-vault",
            "Master Vault",
            "mastervault",
        ] {
            out.push(base.join(name));
        }
    }
    out
}

fn settings_vault_path() -> Option<PathBuf> {
    for dir in user_data_dirs() {
        let p = dir.join("settings.json");
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                if let Some(vp) = v.get("vaultPath").and_then(|x| x.as_str()) {
                    if !vp.is_empty() {
                        let pb = PathBuf::from(vp);
                        if pb.exists() {
                            return Some(pb);
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn default_save_dir() -> PathBuf {
    if let Some(p) =
        directories::ProjectDirs::from("com", "norythm", "norythmpasswd")
            .map(|p| p.config_dir().to_path_buf())
    {
        if !p.exists() {
            if let Some(mp) = directories::ProjectDirs::from("com", "norythm", "masterpasswd")
                .map(|p| p.config_dir().to_path_buf())
            {
                if mp.exists() {
                    return mp;
                }
            }
        }
        return p;
    }
    directories::BaseDirs::new()
        .map(|b| {
            let np = b.config_dir().to_path_buf().join("norythmpasswd");
            let mp = b.config_dir().to_path_buf().join("masterpasswd");
            if mp.exists() && !np.exists() {
                mp
            } else {
                np
            }
        })
        .unwrap_or_else(|| PathBuf::from("norythmpasswd"))
}

pub fn legacy_vault_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let native = default_save_dir();
    if native.exists() {
        out.push(native);
    }
    if let Some(p) = settings_vault_path() {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    let media = PathBuf::from("/media/Games/Vaults");
    if media.exists() {
        out.push(media);
    }
    if let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) {
        let hv = home.join("Vaults");
        if hv.exists() {
            out.push(hv);
        }
    }
    for ud in user_data_dirs() {
        let v = ud.join("Vaults");
        if v.exists() {
            out.push(v);
        }
    }
    out
}

pub fn find_vault_file() -> Option<PathBuf> {
    legacy_vault_dirs()
        .into_iter()
        .map(|d| d.join("vault.enc"))
        .find(|p| p.exists())
}

pub fn read_salt(vault_dir: &Path) -> Option<String> {
    let mut candidates = vec![vault_dir.join("security_cfg.json")];
    for ud in user_data_dirs() {
        candidates.push(ud.join(".sysconfig"));
        candidates.push(ud.join("security_cfg.json"));
    }
    for c in candidates {
        if let Ok(s) = std::fs::read_to_string(&c) {
            let parsed = crypto::decode_sys_config(&s)
                .or_else(|| serde_json::from_str(&s).ok());
            if let Some(v) = parsed {
                if let Some(salt) = v.get("salt").and_then(|x| x.as_str()) {
                    return Some(salt.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_payload() -> VaultPayload {
        let mut entry = VaultEntry::default();
        entry.email = "user@example.com".to_string();
        entry.password = "s3cret!".to_string();
        entry.notes = "notes here".to_string();
        entry.section = "Work".to_string();
        entry.starred = true;
        entry.last_modified = "2026-01-01T00:00:00Z".to_string();
        entry.custom_fields = vec![CustomField {
            key: "PIN".to_string(),
            value: "1234".to_string(),
        }];

        let mut vault = HashMap::new();
        vault.insert("GitHub".to_string(), entry);

        let mut backups = HashMap::new();
        backups.insert(
            "GitHub".to_string(),
            vec!["code-1".to_string(), "code-2".to_string()],
        );

        let mut wallet = Wallet::default();
        wallet.id = "WALLET_1".to_string();
        wallet.wallet_type = "CRYPTO".to_string();
        wallet.name = "Cold".to_string();
        wallet.fields = vec![WalletField {
            name: "Address".to_string(),
            value: "0xabc".to_string(),
            is_secret: false,
        }];

        let mut payload = VaultPayload::default();
        payload.vault = vault;
        payload.backups = backups;
        payload.wallets = vec![wallet];
        payload
    }

    #[test]
    fn serialize_encrypt_decrypt_deserialize_roundtrip() {
        let key = crypto::derive_key(b"test-master-password", b"test-salt").expect("derive");
        let payload = mock_payload();

        let json = serde_json::to_vec(&payload).expect("serialize");
        let enc = crypto::encrypt_vault_data(key.as_ref(), &json).expect("encrypt");
        let dec = crypto::decrypt_vault_data(key.as_ref(), &enc).expect("decrypt");
        let back: VaultPayload = serde_json::from_slice(&dec).expect("deserialize");

        assert_eq!(back, payload);
        assert_eq!(back.vault["GitHub"].password, "s3cret!");
        assert_eq!(back.vault["GitHub"].custom_fields[0].key, "PIN");
        assert_eq!(back.backups["GitHub"].len(), 2);
    }

    #[test]
    fn legacy_empty_array_vault_field_parses() {
        let v: VaultPayload =
            serde_json::from_str(r#"{"vault":[],"backups":{},"sectionSettings":{}}"#)
                .expect("legacy init payload");
        assert!(v.vault.is_empty());
    }

    #[test]
    fn sparse_entry_defaults() {
        let v: VaultPayload =
            serde_json::from_str(r#"{"vault":{"X":{"email":"","password":""}}}"#).expect("sparse");
        assert_eq!(v.vault["X"].phone, "");
        assert!(!v.vault["X"].starred);
    }

    #[tokio::test]
    async fn load_save_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mp-test-{}", std::process::id()));
        let path = dir.join("vault.enc");
        let key = crypto::derive_key(b"file-password", b"file-salt").expect("derive");
        let payload = mock_payload();

        save_vault(&path, key.as_ref(), &payload).await.expect("save");
        let loaded = load_vault(&path, key.as_ref()).await.expect("load");
        assert_eq!(loaded, payload);

        let (loaded_auto, _active_key, _upgraded) =
            load_vault_with_password(&path, "file-password", b"file-salt")
                .await
                .expect("load with password");
        assert_eq!(loaded_auto, payload);

        tokio::fs::remove_dir_all(&dir).await.ok();
    }
}
