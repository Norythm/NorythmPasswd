use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::vault::VaultPayload as Vault;

#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub vault: Arc<RwLock<Option<Vault>>>,
    pub master_key: Arc<RwLock<Option<Zeroizing<[u8; KEY_LEN]>>>>,
    pub vault_dir: Arc<RwLock<Option<PathBuf>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Option<Vault> {
        self.vault.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_vault(&self, payload: Vault) {
        let mut guard = self.vault.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(payload);
    }

    pub fn unlock(&self, key: Zeroizing<[u8; KEY_LEN]>) {
        let mut guard = self.master_key.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(key);
    }

    pub fn lock(&self) {
        let mut key_guard = self.master_key.write().unwrap_or_else(|e| e.into_inner());
        *key_guard = None;

        let mut vault_guard = self.vault.write().unwrap_or_else(|e| e.into_inner());
        *vault_guard = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }
}
