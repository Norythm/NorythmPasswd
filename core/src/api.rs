use std::sync::Arc;

use crate::crypto;
use crate::state::AppState;

pub struct AppEngine {
    state: AppState,
    _rt: tokio::runtime::Runtime,
}

pub fn new_engine() -> Arc<AppEngine> {
    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    Arc::new(AppEngine {
        state: AppState::new(),
        _rt,
    })
}

impl AppEngine {
    pub fn unlock(&self, password: String) -> bool {
        if let Ok(key) = crypto::derive_key(password.as_bytes(), b"") {
            self.state.unlock(key);
            true
        } else {
            false
        }
    }

    pub fn lock(&self) {
        self.state.lock();
    }

    pub fn get_vault_json(&self) -> String {
        let snap = self.state.snapshot();
        serde_json::to_string(&snap).unwrap_or_else(|_| "{}".to_string())
    }
}
