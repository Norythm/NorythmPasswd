use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use arboard::Clipboard;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use colored::*;
use masterpasswd_core::crypto::{self, KEY_LEN, SALT_LEN};
use masterpasswd_core::vault::{load_vault_with_password, save_vault, VaultEntry, VaultPayload};
use rand::Rng;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "np",
    author = "Norythm",
    version = "0.1.0",
    about = "NorythmPasswd: Fast, secure local vault CLI"
)]
struct Cli {
    /// Path to vault.enc (defaults to ~/.local/share/norythmpasswd/vault.enc or ./vault.enc)
    #[arg(short, long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all or filtered accounts
    #[command(alias = "ls")]
    List {
        /// Optional search query (matches service name, username, or section)
        query: Option<String>,
        /// Filter by specific section
        #[arg(short, long)]
        section: Option<String>,
    },

    /// List all vault categories/sections with account counts
    Sections,

    /// Get account details and copy password to clipboard
    Get {
        /// Name of the service to look up
        service: String,
        /// Print password directly to terminal instead of copying to clipboard
        #[arg(short, long)]
        show: bool,
        /// Copy email to clipboard instead of password
        #[arg(short, long)]
        email: bool,
        /// Copy live 2FA code to clipboard instead of password
        #[arg(short, long, alias = "2fa")]
        totp: bool,
        /// View or copy 2FA backup recovery codes
        #[arg(short, long)]
        codes: bool,
    },

    /// Manage 2FA emergency backup recovery codes
    #[command(alias = "backup-codes", alias = "backupcodes")]
    Codes {
        /// Optional service name to view or copy
        service: Option<String>,
        /// Copy the first available backup code to clipboard
        #[arg(short, long)]
        copy: bool,
        /// Add backup codes for this service
        #[arg(short, long)]
        add: bool,
        /// Remove backup codes for this service
        #[arg(short, long)]
        rm: bool,
    },

    /// Generate live 6-digit 2FA / TOTP code and copy to clipboard
    #[command(alias = "2fa")]
    Totp {
        /// Name of the service
        service: String,
    },

    /// Add a new account to the vault
    Add {
        /// Service name
        service: Option<String>,
    },

    /// Edit an existing account
    Edit {
        /// Service name
        service: String,
    },

    /// Remove an account from the vault
    #[command(alias = "delete")]
    Rm {
        /// Service name
        service: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Create a complete timestamped backup (both encrypted and decrypted files)
    Backup {
        /// Destination folder (defaults to /media/Games/MasterPasswd/01-MY-PASSWORDS/ or ./)
        destination: Option<PathBuf>,
    },

    /// Import accounts from a backup file (.json, .vault, .enc, or .csv)
    Import {
        /// Path to backup file (.json, .vault, .enc, or .csv)
        file: PathBuf,
    },

    /// Export vault accounts to text, CSV, JSON, or encrypted vault
    Export {
        /// Export to readable Markdown
        #[arg(long)]
        md: Option<PathBuf>,
        /// Export to plaintext
        #[arg(long)]
        txt: Option<PathBuf>,
        /// Export to Bitwarden-compatible CSV
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Export to raw decrypted JSON
        #[arg(long)]
        json: Option<PathBuf>,
        /// Export to encrypted standalone vault (.vault or .enc)
        #[arg(long, alias = "enc")]
        vault: Option<PathBuf>,
    },

    /// Generate a strong random password
    #[command(alias = "gen")]
    Passgen {
        /// Password length
        #[arg(short, long, default_value_t = 20)]
        length: usize,
    },

    /// View or change the persistent runtime vault location
    Path {
        /// New path for runtime vault.enc (e.g. /media/Games/Passwords/vault.enc)
        new_path: Option<PathBuf>,
        /// Reset runtime path back to system default (~/.local/share/masterpasswd/vault.enc)
        #[arg(long)]
        reset: bool,
    },
}

fn get_config_path() -> PathBuf {
    if let Some(b) = directories::BaseDirs::new() {
        let np_path = b.config_dir().join("norythmpasswd").join("config.json");
        if np_path.exists() {
            return np_path;
        }
        let mp_path = b.config_dir().join("masterpasswd").join("config.json");
        if mp_path.exists() {
            return mp_path;
        }
        return np_path;
    }
    PathBuf::from(".np_config.json")
}

fn resolve_vault_paths(custom_vault: Option<&PathBuf>) -> (PathBuf, PathBuf) {
    if let Some(p) = custom_vault {
        let abs = resolve_destination_path(p);
        let salt = abs.with_extension("salt");
        return (abs, salt);
    }
    if let Ok(env_path) = std::env::var("NP_VAULT").or_else(|_| std::env::var("MP_VAULT")) {
        if !env_path.trim().is_empty() {
            let p = resolve_destination_path(&PathBuf::from(env_path.trim()));
            let salt = p.with_extension("salt");
            return (p, salt);
        }
    }
    let cfg_path = get_config_path();
    if cfg_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&cfg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(s) = val.get("vault_path").and_then(|x| x.as_str()) {
                    if !s.trim().is_empty() {
                        let p = resolve_destination_path(&PathBuf::from(s.trim()));
                        let salt = p.with_extension("salt");
                        return (p, salt);
                    }
                }
            }
        }
    }
    let cwd_vault = PathBuf::from("vault.enc");
    if cwd_vault.exists() {
        return (cwd_vault, PathBuf::from("vault.salt"));
    }
    let base = directories::BaseDirs::new()
        .map(|b| {
            let mp_base = b.data_local_dir().join("masterpasswd");
            let np_base = b.data_local_dir().join("norythmpasswd");
            if mp_base.join("vault.enc").exists() && !np_base.join("vault.enc").exists() {
                mp_base
            } else {
                np_base
            }
        })
        .unwrap_or_else(|| PathBuf::from(".norythmpasswd"));
    let _ = std::fs::create_dir_all(&base);
    (base.join("vault.enc"), base.join("vault.salt"))
}

fn get_or_create_salt(salt_path: &Path) -> Vec<u8> {
    if salt_path.exists() {
        if let Ok(content) = std::fs::read_to_string(salt_path) {
            let hex_clean = content.trim();
            if let Ok(bytes) = hex::decode(hex_clean) {
                if bytes.len() == SALT_LEN {
                    return bytes;
                }
            }
        }
    }
    let new_salt = crypto::generate_salt();
    let hex_salt = hex::encode(new_salt);
    if let Some(parent) = salt_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(salt_path, hex_salt);
    new_salt.to_vec()
}

fn prompt_password(prompt: &str) -> String {
    if let Ok(env_pass) = std::env::var("NP_PASSWORD").or_else(|_| std::env::var("MP_PASSWORD")) {
        if !env_pass.is_empty() {
            return env_pass;
        }
    }
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn prompt_line(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
    buf.trim().to_string()
}

fn generate_totp_code(secret: &str) -> Option<(String, u64)> {
    let s = secret.trim();
    if s.is_empty() {
        return None;
    }
    if s.to_lowercase().starts_with("otpauth://") {
        if let Ok(t) = totp_rs::TOTP::from_url(s) {
            if let Ok(code) = t.generate_current() {
                let ttl = t.ttl().unwrap_or(30);
                return Some((code, ttl));
            }
        }
        if let Ok(t) = totp_rs::TOTP::from_url_unchecked(s) {
            if let Ok(code) = t.generate_current() {
                let ttl = t.ttl().unwrap_or(30);
                return Some((code, ttl));
            }
        }
    }
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .trim_end_matches('=')
        .to_uppercase();

    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &clean)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, s.trim()))
        .or_else(|| base32::decode(base32::Alphabet::Crockford, &clean))
        .or_else(|| totp_rs::Secret::Encoded(clean.clone()).to_bytes().ok())
        .unwrap_or_else(|| clean.into_bytes());

    let t = totp_rs::TOTP::new_unchecked(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        None,
        "".to_string(),
    );
    let code = t.generate_current().ok()?;
    let ttl = t.ttl().unwrap_or(30);
    Some((code, ttl))
}

fn resolve_destination_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(p)
    } else {
        p.to_path_buf()
    }
}

fn create_vault_archive(path: &Path, salt_hex: &str, enc_bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::File::create(path).map_err(|e| format!("Failed to create file: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("security_cfg.json", options)
        .map_err(|e| format!("Zip error: {e}"))?;
    let sec_json = serde_json::json!({
        "salt": salt_hex,
        "hash": ""
    });
    let sec_b64 = base64::engine::general_purpose::STANDARD.encode(sec_json.to_string());
    zip.write_all(sec_b64.as_bytes())
        .map_err(|e| format!("Zip write error: {e}"))?;

    zip.start_file("vault.enc", options)
        .map_err(|e| format!("Zip error: {e}"))?;
    zip.write_all(enc_bytes)
        .map_err(|e| format!("Zip write error: {e}"))?;

    zip.finish().map_err(|e| format!("Zip finish error: {e}"))?;
    Ok(())
}

fn read_vault_archive(path: &Path) -> Result<(String, Vec<u8>), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("Invalid zip archive: {e}"))?;

    let mut salt_hex = String::new();
    let mut enc_bytes = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("Zip read error: {e}"))?;
        let name = file.name().to_string();
        if name.ends_with("security_cfg.json") || name.ends_with(".sysconfig") {
            let mut content = String::new();
            let _ = file.read_to_string(&mut content);
            if let Some(cfg) = crypto::decode_sys_config(&content) {
                if let Some(s) = cfg.get("salt").and_then(|x| x.as_str()) {
                    salt_hex = s.to_string();
                }
            } else if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(s) = cfg.get("salt").and_then(|x| x.as_str()) {
                    salt_hex = s.to_string();
                }
            }
        } else if name.ends_with("vault.enc") {
            let _ = file.read_to_end(&mut enc_bytes);
        }
    }

    if salt_hex.is_empty() || enc_bytes.is_empty() {
        return Err("Archive does not contain valid security_cfg.json and vault.enc".into());
    }
    Ok((salt_hex, enc_bytes))
}

fn format_txt_vault(payload: &VaultPayload) -> String {
    let mut out = format!("=== PASSWORDS VAULT (Total: {}) ===\n\n", payload.vault.len());
    let mut sorted: Vec<(&String, &VaultEntry)> = payload.vault.iter().collect();
    sorted.sort_by(|a, b| a.1.section.cmp(&b.1.section).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase())));

    let mut current_sec = String::new();
    for (name, entry) in sorted {
        let sec = if entry.section.is_empty() { "Uncategorized".to_string() } else { entry.section.clone() };
        if sec != current_sec {
            current_sec = sec;
            out.push_str(&format!("========================================\nSECTION: {}\n========================================\n\n", current_sec));
        }
        let star = if entry.starred { "[*] " } else { "" };
        out.push_str(&format!("Service     : {}{}\n", star, name));
        if !entry.email.is_empty() {
            out.push_str(&format!("User/Email  : {}\n", entry.email));
        }
        if !entry.password.is_empty() {
            out.push_str(&format!("Password    : {}\n", entry.password));
        }
        if !entry.totp_secret.is_empty() {
            out.push_str(&format!("2FA/TOTP    : {}\n", entry.totp_secret));
        }
        if !entry.phone.is_empty() {
            out.push_str(&format!("Phone       : {}\n", entry.phone));
        }
        if !entry.notes.is_empty() {
            out.push_str(&format!("Notes       : {}\n", entry.notes));
        }
        for cf in &entry.custom_fields {
            out.push_str(&format!("{:<12}: {}\n", cf.key, cf.value));
        }
        if let Some(codes) = payload.backups.get(name) {
            if !codes.is_empty() {
                out.push_str(&format!("Backup Codes: {}\n", codes.join(", ")));
            }
        }
        out.push_str("----------------------------------------\n\n");
    }

    let standalone_codes: Vec<(&String, &Vec<String>)> = payload
        .backups
        .iter()
        .filter(|(s, _)| !payload.vault.contains_key(*s))
        .collect();

    if !standalone_codes.is_empty() {
        out.push_str("========================================\nSECTION: Standalone 2FA Backup Codes\n========================================\n\n");
        for (s, codes) in standalone_codes {
            out.push_str(&format!("Service     : {}\n", s));
            out.push_str(&format!("Backup Codes: {}\n", codes.join(", ")));
            out.push_str("----------------------------------------\n\n");
        }
    }

    out
}

fn format_md_vault(payload: &VaultPayload) -> String {
    let mut out = format!("# Complete Passwords & 2FA Vault\n\n> Total Accounts: {}\n\n", payload.vault.len());
    let mut sorted: Vec<(&String, &VaultEntry)> = payload.vault.iter().collect();
    sorted.sort_by(|a, b| a.1.section.cmp(&b.1.section).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase())));

    let mut current_sec = String::new();
    for (name, entry) in sorted {
        let sec = if entry.section.is_empty() { "Uncategorized".to_string() } else { entry.section.clone() };
        if sec != current_sec {
            current_sec = sec;
            out.push_str(&format!("## {}\n\n", current_sec));
        }
        let star = if entry.starred { "⭐ " } else { "" };
        out.push_str(&format!("### {}{}\n", star, name));
        if !entry.email.is_empty() {
            out.push_str(&format!("- **Username / Email**: `{}`\n", entry.email));
        }
        if !entry.password.is_empty() {
            out.push_str(&format!("- **Password**: `{}`\n", entry.password));
        }
        if !entry.totp_secret.is_empty() {
            out.push_str(&format!("- **🔑 2FA / TOTP Secret**: `{}`\n", entry.totp_secret));
        }
        if !entry.phone.is_empty() {
            out.push_str(&format!("- **Phone**: `{}`\n", entry.phone));
        }
        if !entry.notes.is_empty() {
            out.push_str(&format!("- **Notes**: {}\n", entry.notes));
        }
        for cf in &entry.custom_fields {
            out.push_str(&format!("- **{}**: `{}`\n", cf.key, cf.value));
        }
        if let Some(codes) = payload.backups.get(name) {
            if !codes.is_empty() {
                out.push_str("- **🛡️ 2FA Backup Recovery Codes**:\n");
                for c in codes {
                    out.push_str(&format!("  - `{}`\n", c));
                }
            }
        }
        out.push_str("\n");
    }

    let standalone_codes: Vec<(&String, &Vec<String>)> = payload
        .backups
        .iter()
        .filter(|(s, _)| !payload.vault.contains_key(*s))
        .collect();

    if !standalone_codes.is_empty() {
        out.push_str("## Standalone 2FA Backup Codes\n\n");
        for (s, codes) in standalone_codes {
            out.push_str(&format!("### 🛡️ {}\n\n", s));
            out.push_str("- **Recovery Codes**:\n");
            for c in codes {
                out.push_str(&format!("  - `{}`\n", c));
            }
            out.push('\n');
        }
    }

    out
}

fn format_txt_backup_codes(payload: &VaultPayload) -> String {
    let mut total_codes = 0;
    for codes in payload.backups.values() {
        total_codes += codes.len();
    }
    let mut out = format!(
        "=== 2FA EMERGENCY BACKUP RECOVERY CODES ===\nTotal Services: {} | Total Codes: {}\nGenerated: {}\n\n",
        payload.backups.len(),
        total_codes,
        chrono_lite_timestamp()
    );

    let mut sorted: Vec<(&String, &Vec<String>)> = payload.backups.iter().collect();
    sorted.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    for (service, codes) in sorted {
        out.push_str("========================================\n");
        out.push_str(&format!("SERVICE: {} ({} recovery codes)\n", service, codes.len()));
        if let Some(entry) = payload.vault.get(service) {
            if !entry.email.is_empty() {
                out.push_str(&format!("ACCOUNT: {}\n", entry.email));
            }
        }
        out.push_str("========================================\n");
        for (i, code) in codes.iter().enumerate() {
            out.push_str(&format!("{:2}. {}\n", i + 1, code));
        }
        out.push_str("\n");
    }
    out
}

fn format_md_backup_codes(payload: &VaultPayload) -> String {
    let mut total_codes = 0;
    for codes in payload.backups.values() {
        total_codes += codes.len();
    }
    let mut out = format!(
        "# 🛡️ 2FA Emergency Backup Recovery Codes\n\n> **Total Services**: {} | **Total Backup Codes**: {} | **Generated**: `{}`\n\n",
        payload.backups.len(),
        total_codes,
        chrono_lite_timestamp()
    );

    let mut sorted: Vec<(&String, &Vec<String>)> = payload.backups.iter().collect();
    sorted.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    for (service, codes) in sorted {
        let account_str = if let Some(entry) = payload.vault.get(service) {
            if !entry.email.is_empty() {
                format!(" (`{}`)", entry.email)
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        out.push_str(&format!("## 🔑 {}{}\n\n", service, account_str));
        out.push_str(&format!("*Total Available Codes: {}*\n\n", codes.len()));
        for (i, code) in codes.iter().enumerate() {
            out.push_str(&format!("{}. `{}`\n", i + 1, code));
        }
        out.push_str("\n---\n\n");
    }
    out
}

fn format_csv_vault(payload: &VaultPayload) -> String {
    let mut out = String::from("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n");
    for (name, item) in &payload.vault {
        let folder = if item.section.is_empty() { "Uncategorized" } else { &item.section };
        let fav = if item.starred { "1" } else { "0" };
        let mut notes_parts = Vec::new();
        if !item.phone.is_empty() {
            notes_parts.push(format!("Phone: {}", item.phone));
        }
        if !item.notes.is_empty() {
            notes_parts.push(item.notes.clone());
        }
        for cf in &item.custom_fields {
            notes_parts.push(format!("{}: {}", cf.key, cf.value));
        }
        if let Some(codes) = payload.backups.get(name) {
            if !codes.is_empty() {
                notes_parts.push("=== 2FA BACKUP CODES ===".to_string());
                notes_parts.extend(codes.clone());
            }
        }
        let notes_escaped = notes_parts.join("\n").replace('"', "\"\"");
        out.push_str(&format!(
            "\"{}\",{},login,\"{}\",\"{}\",\"\",0,\"\",\"{}\",\"{}\",\"{}\"\n",
            folder,
            fav,
            name.replace('"', "\"\""),
            notes_escaped,
            item.email.replace('"', "\"\""),
            item.password.replace('"', "\"\""),
            item.totp_secret.replace('"', "\"\"")
        ));
    }
    out
}

fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

async fn get_unlocked_vault(
    vault_path: &Path,
    salt_path: &Path,
) -> Result<(VaultPayload, zeroize::Zeroizing<[u8; KEY_LEN]>), String> {
    let salt = get_or_create_salt(salt_path);
    if !vault_path.exists() {
        println!("{}", "No vault found. Creating a new one.".yellow());
        let mut pass1 = prompt_password("Set Master Password: ");
        if pass1.is_empty() {
            return Err("Password cannot be empty".into());
        }
        let mut pass2 = prompt_password("Confirm Master Password: ");
        if pass1 != pass2 {
            pass1.zeroize();
            pass2.zeroize();
            return Err("Passwords do not match".into());
        }
        let key = crypto::derive_key(pass1.as_bytes(), &salt)
            .map_err(|e| format!("Failed to derive key: {e}"))?;
        pass1.zeroize();
        pass2.zeroize();
        let payload = VaultPayload::default();
        save_vault(vault_path, key.as_ref(), &payload)
            .await
            .map_err(|e| format!("Failed to initialize vault: {e}"))?;
        println!("{}", "Vault created successfully with Argon2id encryption.".green());
        return Ok((payload, key));
    }

    let mut pass = prompt_password("Master Password: ");
    let (payload, key, upgraded) = load_vault_with_password(vault_path, &pass, &salt)
        .await
        .map_err(|_| {
            pass.zeroize();
            "Invalid password or corrupted vault file.".to_string()
        })?;
    pass.zeroize();

    if upgraded {
        let _ = save_vault(vault_path, key.as_ref(), &payload).await;
    }

    Ok((payload, key))
}

async fn save_vault_and_sync(
    vault_path: &Path,
    salt_path: &Path,
    key: &[u8],
    payload: &VaultPayload,
) -> Result<(), String> {
    save_vault(vault_path, key, payload)
        .await
        .map_err(|e| format!("Failed to save vault: {e}"))?;

    if let Some(b) = directories::BaseDirs::new() {
        for dir_name in ["norythmpasswd", "masterpasswd"] {
            let base = b.data_local_dir().join(dir_name);
            let mirror_v = base.join("vault.enc");
            let mirror_s = base.join("vault.salt");
            if vault_path != &mirror_v {
                let _ = std::fs::create_dir_all(&base);
                let _ = std::fs::copy(vault_path, &mirror_v);
                if salt_path.exists() {
                    let _ = std::fs::copy(salt_path, &mirror_s);
                }
            }
        }
    }

    let backup_dir = match vault_path.parent() {
        Some(p) => p.join("01-MASTER-BACKUPS"),
        None => PathBuf::from("01-MASTER-BACKUPS"),
    };
    let _ = std::fs::create_dir_all(&backup_dir);

    let json_path = backup_dir.join("MASTER_VAULT_ALL_IN_ONE.json");
        if let Ok(raw_json_str) = serde_json::to_string_pretty(payload) {
            let _ = std::fs::write(json_path, raw_json_str);
        }

        let txt_path = backup_dir.join("MASTER_VAULT_ALL_IN_ONE.txt");
        let txt_str = format_txt_vault(payload);
        let _ = std::fs::write(txt_path, txt_str);

        let md_path = backup_dir.join("MASTER_VAULT_ALL_IN_ONE.md");
        let md_str = format_md_vault(payload);
        let _ = std::fs::write(md_path, md_str);

        let csv_path = backup_dir.join("MASTER_VAULT_ALL_IN_ONE.csv");
        let csv_str = format_csv_vault(payload);
        let _ = std::fs::write(csv_path, csv_str);

        let codes_txt_path = backup_dir.join("MASTER_BACKUP_CODES_ALL_IN_ONE.txt");
        let codes_txt_str = format_txt_backup_codes(payload);
        let _ = std::fs::write(codes_txt_path, codes_txt_str);

        let codes_md_path = backup_dir.join("MASTER_BACKUP_CODES_ALL_IN_ONE.md");
        let codes_md_str = format_md_backup_codes(payload);
        let _ = std::fs::write(codes_md_path, codes_md_str);

        let codes_json_path = backup_dir.join("MASTER_BACKUP_CODES_ALL_IN_ONE.json");
        if let Ok(codes_json_str) = serde_json::to_string_pretty(&payload.backups) {
            let _ = std::fs::write(codes_json_path, codes_json_str);
        }

        let enc_archive = backup_dir.join("MASTER_VAULT_ALL_IN_ONE.vault");
        if let Ok(raw_json_bytes) = serde_json::to_vec(payload) {
            if let Ok(enc_bytes) = crypto::encrypt_vault_data(key, &raw_json_bytes) {
                let salt_bytes = get_or_create_salt(salt_path);
                let salt_hex = hex::encode(salt_bytes);
                let _ = create_vault_archive(&enc_archive, &salt_hex, &enc_bytes);
            }
        }

    Ok(())
}

fn copy_to_clipboard_with_timeout(secret: &str, service_name: &str, timeout_secs: u64) {
    let mut copied = false;

    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        if let Ok(mut child) = std::process::Command::new("wl-copy")
            .arg("-n")
            .arg("--sensitive")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(secret.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                copied = true;
                let _ = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(format!("sleep {} && wl-copy -c", timeout_secs))
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        }
    }

    if !copied && std::env::var("DISPLAY").is_ok() {
        if let Ok(mut child) = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(secret.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                copied = true;
                let _ = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(format!("sleep {} && xclip -selection clipboard </dev/null", timeout_secs))
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        }

        if !copied {
            if let Ok(mut child) = std::process::Command::new("xsel")
                .args(["--clipboard", "--input"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(secret.as_bytes());
                }
                if child.wait().map(|s| s.success()).unwrap_or(false) {
                    copied = true;
                    let _ = std::process::Command::new("sh")
                        .arg("-c")
                        .arg(format!("sleep {} && xsel --clipboard --clear", timeout_secs))
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                }
            }
        }
    }

    if !copied {
        if let Ok(mut cb) = Clipboard::new() {
            if cb.set_text(secret).is_ok() {
                copied = true;
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::process::CommandExt;
                    let _ = std::process::Command::new("powershell")
                        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &format!("Start-Sleep -Seconds {}; Set-Clipboard -Value ''", timeout_secs)])
                        .creation_flags(0x08000000)
                        .spawn();
                }
            }
        }
    }

    if copied {
        println!(
            "{} Copied '{}' to clipboard! (auto-clears in {}s)",
            "✔".green().bold(),
            service_name.cyan(),
            timeout_secs
        );
    } else {
        eprintln!(
            "{} Could not copy to clipboard. Use '--show' or '-s' to reveal.",
            "Warning:".yellow().bold()
        );
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let (vault_path, salt_path) = resolve_vault_paths(cli.vault.as_ref());

    match cli.command {
        Commands::Passgen { length } => {
            let pass = generate_random_password(length);
            println!("Generated Password: {}", pass.bold().green());
        }

        Commands::Path { new_path, reset } => {
            let cfg_path = get_config_path();
            if reset {
                if cfg_path.exists() {
                    let _ = std::fs::remove_file(&cfg_path);
                }
                println!("{} Reset runtime vault path to default.", "✔".green().bold());
                let (default_v, default_s) = resolve_vault_paths(None);
                println!("Active Vault: {}", default_v.display().to_string().cyan());
                println!("Active Salt : {}", default_s.display().to_string().cyan());
                return;
            }

            if let Some(np) = new_path {
                let abs = resolve_destination_path(&np);
                let salt_target = abs.with_extension("salt");
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                if !abs.exists() && vault_path.exists() {
                    let _ = std::fs::copy(&vault_path, &abs);
                    if salt_path.exists() {
                        let _ = std::fs::copy(&salt_path, &salt_target);
                    }
                    println!("{} Migrated existing vault data to new location!", "✔".green().bold());
                }

                if let Some(parent) = cfg_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let cfg_json = serde_json::json!({
                    "vault_path": abs.to_string_lossy().to_string()
                });
                if let Err(e) = std::fs::write(&cfg_path, cfg_json.to_string()) {
                    eprintln!("{}: Failed to save configuration: {}", "Error".red().bold(), e);
                    return;
                }
                println!("{} Runtime vault path updated to {}", "✔".green().bold(), abs.display().to_string().cyan());
                println!("  Salt file: {}", salt_target.display().to_string().cyan());
                println!("  Config saved to: {}", cfg_path.display());
            } else {
                let (cur_v, cur_s) = resolve_vault_paths(None);
                println!("\n{}", "=== MP RUNTIME VAULT LOCATION ===".bold().cyan());
                println!("Vault File: {}", cur_v.display().to_string().green());
                println!("Salt File : {}", cur_s.display().to_string().green());
                println!("Config    : {}", cfg_path.display());
                if cur_v.starts_with("/media/Games") {
                    println!("\n🛡️  Status: {} (Stored on persistent /media/Games drive, safe from OS reinstall)", "PROTECTED".green().bold());
                } else {
                    println!("\nℹ️  Status: Active. You can relocate anytime via '{}'.", "np path <custom_path>".cyan().bold());
                }
            }
        }

        Commands::List { query, section } => {
            let (payload, _) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let q = query.as_deref().unwrap_or("").to_lowercase();
            let sec_filter = section.as_deref().unwrap_or("").to_lowercase();

            let mut matched: Vec<(&String, &VaultEntry)> = payload
                .vault
                .iter()
                .filter(|(name, entry)| {
                    let matches_q = q.is_empty()
                        || name.to_lowercase().contains(&q)
                        || entry.email.to_lowercase().contains(&q)
                        || entry.section.to_lowercase().contains(&q);
                    let matches_sec =
                        sec_filter.is_empty() || entry.section.to_lowercase() == sec_filter;
                    matches_q && matches_sec
                })
                .collect();

            matched.sort_by(|a, b| {
                a.1.section
                    .cmp(&b.1.section)
                    .then_with(|| b.1.starred.cmp(&a.1.starred))
                    .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
            });

            if matched.is_empty() {
                println!("{}", "No accounts matched your query.".yellow());
                return;
            }

            println!(
                "\n{} (Found {} accounts in {})\n",
                "VAULT ACCOUNTS".bold().underline(),
                matched.len().to_string().cyan(),
                vault_path.display()
            );

            let mut current_section = String::new();
            for (name, entry) in matched {
                let sec = if entry.section.is_empty() {
                    "Uncategorized".to_string()
                } else {
                    entry.section.clone()
                };

                if sec != current_section {
                    current_section = sec;
                    println!("\n📁 {}", current_section.bold().magenta());
                }

                let star = if entry.starred { "⭐ " } else { "   " };
                let email_str = if entry.email.is_empty() {
                    "-".dimmed()
                } else {
                    entry.email.as_str().normal()
                };

                println!(
                    "  {}[{}] {}  ({})",
                    star,
                    name.bold().cyan(),
                    email_str,
                    if entry.password.is_empty() {
                        "no password".dimmed()
                    } else {
                        "••••••••".dimmed()
                    }
                );
            }
            println!();

            if !payload.backups.is_empty() {
                let total_backup_codes: usize = payload.backups.values().map(|c| c.len()).sum();
                println!(
                    "🛡️  {} ({} services, {} recovery codes stored) -> Run {} to view or copy\n",
                    "2FA BACKUP CODES".bold().underline().cyan(),
                    payload.backups.len().to_string().green().bold(),
                    total_backup_codes.to_string().yellow().bold(),
                    "np codes".green().bold()
                );
            }
        }

        Commands::Sections => {
            let (payload, _) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let mut sec_counts: HashMap<String, usize> = HashMap::new();
            for entry in payload.vault.values() {
                let s = if entry.section.trim().is_empty() {
                    "Uncategorized".to_string()
                } else {
                    entry.section.trim().to_string()
                };
                *sec_counts.entry(s).or_default() += 1;
            }

            let mut sorted: Vec<(String, usize)> = sec_counts.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            println!(
                "\n{} ({} total categories)\n",
                "VAULT CATEGORIES".bold().underline(),
                sorted.len().to_string().cyan()
            );

            for (sec, count) in &sorted {
                println!(
                    "  📁 {:<20} {}",
                    sec.bold().magenta(),
                    format!("({} accounts)", count).cyan()
                );
            }
            println!();
        }

        Commands::Get { service, show, email, totp, codes } => {
            let (payload, _) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let exact = payload
                .vault
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&service));

            let (name, entry) = match exact {
                Some(pair) => pair,
                None => {
                    let matches: Vec<(&String, &VaultEntry)> = payload
                        .vault
                        .iter()
                        .filter(|(k, _)| k.to_lowercase().contains(&service.to_lowercase()))
                        .collect();

                    if matches.is_empty() {
                        eprintln!(
                            "{}: Account '{}' not found.",
                            "Error".red().bold(),
                            service
                        );
                        std::process::exit(1);
                    } else if matches.len() == 1 {
                        matches[0]
                    } else {
                        println!("\n{}", format!("Multiple accounts found for '{}':", service).yellow().bold());
                        for (i, (m_name, m_entry)) in matches.iter().enumerate() {
                            let email_str = if m_entry.email.is_empty() {
                                "".to_string()
                            } else {
                                format!(" ({})", m_entry.email)
                            };
                            let sec_str = if m_entry.section.is_empty() {
                                "".to_string()
                            } else {
                                format!(" [{}]", m_entry.section.magenta())
                            };
                            println!("  [{}] {}{}{}", i + 1, m_name.cyan().bold(), email_str.dimmed(), sec_str);
                        }
                        let choice = prompt_line(&format!("\nSelect account [1-{}] (default: 1): ", matches.len()));
                        let sel_idx = choice.parse::<usize>().unwrap_or(1);
                        let sel_idx = if sel_idx > 0 && sel_idx <= matches.len() {
                            sel_idx - 1
                        } else {
                            0
                        };
                        matches[sel_idx]
                    }
                }
            };

            println!("\n{}", format!("=== {} ===", name).bold().cyan());
            if !entry.section.is_empty() {
                println!("{}: {}", "Section".dimmed(), entry.section);
            }
            if !entry.email.is_empty() {
                println!("{}: {}", "Username/Email".bold(), entry.email.green());
            }

            let live_totp = if !entry.totp_secret.is_empty() {
                generate_totp_code(&entry.totp_secret)
            } else {
                None
            };

            if let Some((ref code, ttl)) = live_totp {
                println!("{}: {} (valid for {}s)", "🔑 Live 2FA Code".bold().green(), code.bold(), ttl);
            } else if !entry.totp_secret.is_empty() {
                println!("{}: {}", "🔑 2FA / TOTP Secret".bold().yellow(), entry.totp_secret);
            }

            if let Some(codes) = payload.backups.get(name) {
                if !codes.is_empty() {
                    println!("{}: {}", "🛡️ 2FA Backup Codes".bold().magenta(), codes.join(", "));
                }
            }
            if !entry.phone.is_empty() {
                println!("{}: {}", "Phone".dimmed(), entry.phone);
            }
            if !entry.notes.is_empty() {
                println!("{}: {}", "Notes".dimmed(), entry.notes);
            }
            for cf in &entry.custom_fields {
                println!("{}: {}", cf.key.dimmed(), cf.value);
            }
            if !entry.last_modified.is_empty() {
                println!("{}: {}", "Last Modified".dimmed(), entry.last_modified);
            }

            if show {
                println!("{}: {}", "Password".bold().yellow(), entry.password.bold());
            } else if email {
                copy_to_clipboard_with_timeout(&entry.email, &format!("{} (email)", name), 20);
            } else if totp {
                if let Some((ref code, _)) = live_totp {
                    copy_to_clipboard_with_timeout(code, &format!("{} (2FA code)", name), 20);
                } else {
                    eprintln!("{}", "No 2FA secret configured for this account.".red());
                }
            } else if codes {
                let backup_match = payload.backups.iter().find(|(k, _)| k.eq_ignore_ascii_case(name) || k.to_lowercase().contains(&service.to_lowercase()));
                if let Some((b_name, b_codes)) = backup_match {
                    if let Some(first_code) = b_codes.first() {
                        copy_to_clipboard_with_timeout(first_code, &format!("{} (Backup Code #1)", b_name), 20);
                    }
                } else {
                    eprintln!("{}", "No 2FA backup codes found for this account.".red());
                }
            } else {
                copy_to_clipboard_with_timeout(&entry.password, name, 20);
            }
            println!();
        }

        Commands::Totp { service } => {
            let (payload, _) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let exact = payload
                .vault
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&service));

            let (name, entry) = match exact {
                Some(pair) => pair,
                None => {
                    let matches: Vec<(&String, &VaultEntry)> = payload
                        .vault
                        .iter()
                        .filter(|(k, _)| k.to_lowercase().contains(&service.to_lowercase()))
                        .collect();
                    if matches.is_empty() {
                        eprintln!("{}: Account '{}' not found.", "Error".red().bold(), service);
                        std::process::exit(1);
                    } else if matches.len() == 1 {
                        matches[0]
                    } else {
                        println!("\n{}", format!("Multiple accounts found for '{}':", service).yellow().bold());
                        for (i, (m_name, m_entry)) in matches.iter().enumerate() {
                            let email_str = if m_entry.email.is_empty() {
                                "".to_string()
                            } else {
                                format!(" ({})", m_entry.email)
                            };
                            let sec_str = if m_entry.section.is_empty() {
                                "".to_string()
                            } else {
                                format!(" [{}]", m_entry.section.magenta())
                            };
                            println!("  [{}] {}{}{}", i + 1, m_name.cyan().bold(), email_str.dimmed(), sec_str);
                        }
                        let choice = prompt_line(&format!("\nSelect account [1-{}] (default: 1): ", matches.len()));
                        let sel_idx = choice.parse::<usize>().unwrap_or(1);
                        let sel_idx = if sel_idx > 0 && sel_idx <= matches.len() {
                            sel_idx - 1
                        } else {
                            0
                        };
                        matches[sel_idx]
                    }
                }
            };

            if entry.totp_secret.is_empty() {
                eprintln!("{}: No 2FA secret configured for '{}'.", "Error".red().bold(), name);
                return;
            }

            if let Some((code, ttl)) = generate_totp_code(&entry.totp_secret) {
                println!("\n🔑 Live 2FA for {}: {} (valid for {}s)", name.bold().cyan(), code.bold().green(), ttl);
                copy_to_clipboard_with_timeout(&code, &format!("{} (2FA)", name), 20);
            } else {
                eprintln!("{}: Failed to generate 2FA code from secret.", "Error".red().bold());
            }
            println!();
        }

        Commands::Codes { service, copy: _, add, rm } => {
            let (mut payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if add {
                let svc = match service {
                    Some(s) => s,
                    None => prompt_line("Service name for backup codes: "),
                };
                if svc.trim().is_empty() {
                    eprintln!("{}: Service name cannot be empty.", "Error".red().bold());
                    return;
                }
                println!("{}", "Enter backup codes (comma-separated or space-separated):".cyan());
                let input = prompt_line("Codes: ");
                let new_codes: Vec<String> = input
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                if new_codes.is_empty() {
                    eprintln!("{}: No valid codes provided.", "Error".red().bold());
                    return;
                }
                let count = new_codes.len();
                payload.backups.insert(svc.clone(), new_codes);
                if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                    eprintln!("{}: {}", "Failed to save vault".red().bold(), e);
                    return;
                }
                println!("{} Saved {} backup codes for '{}'!", "✔".green().bold(), count.to_string().cyan(), svc.bold());
                return;
            }

            if rm {
                let svc = match service {
                    Some(s) => s,
                    None => prompt_line("Service name to remove backup codes from: "),
                };
                if payload.backups.remove(&svc).is_some() {
                    if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                        eprintln!("{}: {}", "Failed to save vault".red().bold(), e);
                        return;
                    }
                    println!("{} Removed backup codes for '{}'.", "✔".green().bold(), svc.bold());
                } else {
                    eprintln!("{}: No backup codes found for '{}'.", "Error".red().bold(), svc);
                }
                return;
            }

            if let Some(svc) = service {
                let exact = payload.backups.iter().find(|(k, _)| k.eq_ignore_ascii_case(&svc));
                let (name, codes) = match exact {
                    Some(pair) => pair,
                    None => {
                        let matches: Vec<(&String, &Vec<String>)> = payload
                            .backups
                            .iter()
                            .filter(|(k, _)| k.to_lowercase().contains(&svc.to_lowercase()))
                            .collect();

                        if matches.is_empty() {
                            eprintln!("{}: No backup codes found for '{}'.", "Error".red().bold(), svc);
                            std::process::exit(1);
                        } else if matches.len() == 1 {
                            matches[0]
                        } else {
                            println!("\n{}", format!("Multiple backup code sets found for '{}':", svc).yellow().bold());
                            for (i, (m_name, m_codes)) in matches.iter().enumerate() {
                                println!("  [{}] {} ({} codes)", i + 1, m_name.cyan().bold(), m_codes.len());
                            }
                            let choice = prompt_line(&format!("\nSelect set [1-{}] (default: 1): ", matches.len()));
                            let sel_idx = choice.parse::<usize>().unwrap_or(1);
                            let sel_idx = if sel_idx > 0 && sel_idx <= matches.len() { sel_idx - 1 } else { 0 };
                            matches[sel_idx]
                        }
                    }
                };

                println!("\n{} ({} recovery codes stored)", format!("🛡️  2FA BACKUP CODES FOR '{}'", name).bold().underline().cyan(), codes.len());
                for (i, code) in codes.iter().enumerate() {
                    println!("  {:2}. {}", (i + 1).to_string().dimmed(), code.bold());
                }
                println!();

                if let Some(first_code) = codes.first() {
                    copy_to_clipboard_with_timeout(first_code, &format!("{} (Backup Code #1)", name), 20);
                }
                return;
            }

            if payload.backups.is_empty() {
                println!("{}", "No backup codes currently stored in the vault.".yellow());
                println!("Run {} to add backup codes.", "np codes <service> --add".cyan());
                return;
            }

            let mut sorted: Vec<(&String, &Vec<String>)> = payload.backups.iter().collect();
            sorted.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

            let total_codes: usize = sorted.iter().map(|(_, c)| c.len()).sum();

            println!(
                "\n{} (Found {} services with {} total codes in {})\n",
                "🛡️  2FA BACKUP RECOVERY CODES".bold().underline(),
                sorted.len().to_string().cyan(),
                total_codes.to_string().green().bold(),
                vault_path.display()
            );

            for (name, codes) in sorted {
                let linked_account = if let Some(acc) = payload.vault.get(name) {
                    if !acc.email.is_empty() {
                        format!(" [{}]", acc.email.dimmed())
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                println!(
                    "  🔑 {:<30} {}{}",
                    name.bold().cyan(),
                    format!("({} codes)", codes.len()).yellow(),
                    linked_account
                );
            }

            println!("\n💡 Tip: Run {} to view or copy codes for a service.", "np codes <service>".green());
            println!("💡 Tip: Run {} to add new emergency codes.\n", "np codes <service> --add".green());
        }

        Commands::Add { service } => {
            let (mut payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let name = match service {
                Some(s) if !s.is_empty() => s,
                _ => {
                    let n = prompt_line("Service Name: ");
                    if n.is_empty() {
                        eprintln!("{}", "Service name cannot be empty.".red());
                        return;
                    }
                    n
                }
            };

            if payload.vault.contains_key(&name) {
                eprintln!(
                    "{} Service '{}' already exists. Use 'mp edit' instead.",
                    "Error:".red().bold(),
                    name
                );
                return;
            }

            let email = prompt_line("Username / Email: ");
            let pass_input = prompt_line("Password (press [Enter] to auto-generate): ");
            let password = if pass_input.is_empty() {
                let generated = generate_random_password(20);
                println!("Auto-generated password: {}", generated.bold().green());
                generated
            } else {
                pass_input
            };

            let mut sec_counts: HashMap<String, usize> = HashMap::new();
            for entry in payload.vault.values() {
                let s = if entry.section.trim().is_empty() {
                    "Uncategorized".to_string()
                } else {
                    entry.section.trim().to_string()
                };
                *sec_counts.entry(s).or_default() += 1;
            }
            let mut sorted_secs: Vec<(String, usize)> = sec_counts.into_iter().collect();
            sorted_secs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            println!("\n{}", "Available Sections:".bold().magenta());
            for (i, (s_name, count)) in sorted_secs.iter().enumerate() {
                print!("  [{}] {} ({})", i + 1, s_name.cyan(), count);
                if (i + 1) % 3 == 0 || i + 1 == sorted_secs.len() {
                    println!();
                } else {
                    print!("   ");
                }
            }
            let sec_choice = prompt_line(&format!(
                "Select section [1-{}] or type new name (Enter = Uncategorized): ",
                sorted_secs.len()
            ));
            let section = if sec_choice.is_empty() {
                "Uncategorized".to_string()
            } else if let Ok(num) = sec_choice.parse::<usize>() {
                if num > 0 && num <= sorted_secs.len() {
                    sorted_secs[num - 1].0.clone()
                } else {
                    sec_choice
                }
            } else {
                sec_choice
            };
            let totp_secret = prompt_line("2FA / TOTP Secret [optional]: ");
            let phone = prompt_line("Phone [optional]: ");
            let notes = prompt_line("Notes [optional]: ");
            let star_ans = prompt_line("Star / Favorite? (y/N): ");
            let starred = star_ans.eq_ignore_ascii_case("y") || star_ans.eq_ignore_ascii_case("yes");

            let now = chrono_lite_timestamp();

            let entry = VaultEntry {
                email,
                password,
                phone,
                notes,
                section,
                color: "".to_string(),
                custom_fields: Vec::new(),
                totp_secret,
                starred,
                last_modified: now,
            };

            payload.vault.insert(name.clone(), entry);
            if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                eprintln!("{}: {}", "Failed to save vault".red().bold(), e);
                return;
            }

            println!(
                "{} Account '{}' added successfully!",
                "✔".green().bold(),
                name.cyan()
            );
        }

        Commands::Edit { service } => {
            let (mut payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let entry = match payload.vault.get_mut(&service) {
                Some(e) => e,
                None => {
                    eprintln!("{}: Account '{}' not found.", "Error".red().bold(), service);
                    return;
                }
            };

            println!("Editing '{}' (press [Enter] to keep current value):", service.cyan().bold());
            let new_email = prompt_line(&format!("Username/Email [{}]: ", entry.email));
            if !new_email.is_empty() {
                entry.email = new_email;
            }

            let new_pass = prompt_line("Password [leave blank to keep]: ");
            if !new_pass.is_empty() {
                entry.password = new_pass;
            }

            let new_sec = prompt_line(&format!("Section [{}]: ", entry.section));
            if !new_sec.is_empty() {
                entry.section = new_sec;
            }

            let new_totp = prompt_line(&format!("2FA / TOTP Secret [{}]: ", entry.totp_secret));
            if !new_totp.is_empty() {
                entry.totp_secret = new_totp;
            }

            let new_notes = prompt_line(&format!("Notes [{}]: ", entry.notes));
            if !new_notes.is_empty() {
                entry.notes = new_notes;
            }

            entry.last_modified = chrono_lite_timestamp();

            if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                eprintln!("{}: {}", "Failed to save vault".red().bold(), e);
                return;
            }

            println!("{} Account '{}' updated!", "✔".green().bold(), service.cyan());
        }

        Commands::Rm { service, force } => {
            let (mut payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if !payload.vault.contains_key(&service) {
                eprintln!("{}: Account '{}' not found.", "Error".red().bold(), service);
                return;
            }

            if !force {
                let confirm = prompt_line(&format!(
                    "Are you sure you want to delete '{}'? (y/N): ",
                    service.red().bold()
                ));
                if !confirm.eq_ignore_ascii_case("y") && !confirm.eq_ignore_ascii_case("yes") {
                    println!("Aborted.");
                    return;
                }
            }

            payload.vault.remove(&service);
            if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                eprintln!("{}: {}", "Failed to save vault".red().bold(), e);
                return;
            }

            println!("{} Account '{}' deleted.", "✔".green().bold(), service.cyan());
        }

        Commands::Backup { destination } => {
            let (payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let default_dir = match vault_path.parent() {
                Some(p) => p.join("01-MASTER-BACKUPS"),
                None => PathBuf::from("01-MASTER-BACKUPS"),
            };
            let target_dir = match destination {
                Some(p) => resolve_destination_path(&p),
                None => default_dir,
            };
            let _ = std::fs::create_dir_all(&target_dir);

            let date_str = chrono_lite_date();

            let enc_name = format!("VaultBackup_ENC_{}.vault", date_str);
            let raw_name = format!("VaultBackup_RAW_{}.json", date_str);
            let txt_name = format!("passwords_{}.txt", date_str);
            let md_name = format!("passwords_{}.md", date_str);

            let enc_file = target_dir.join(&enc_name);
            let raw_file = target_dir.join(&raw_name);
            let txt_file = target_dir.join(&txt_name);
            let md_file = target_dir.join(&md_name);

            let raw_json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
            let enc_bytes = match crypto::encrypt_vault_data(key.as_ref(), &raw_json_bytes) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}: Failed to encrypt vault: {}", "Error".red().bold(), e);
                    return;
                }
            };
            let salt_bytes = get_or_create_salt(&salt_path);
            let salt_hex = hex::encode(salt_bytes);
            if let Err(e) = create_vault_archive(&enc_file, &salt_hex, &enc_bytes) {
                eprintln!("{}: Failed to write encrypted backup: {}", "Error".red().bold(), e);
                return;
            }

            let raw_json_str = serde_json::to_string_pretty(&payload).unwrap_or_default();
            let _ = std::fs::write(&raw_file, raw_json_str);

            let txt_str = format_txt_vault(&payload);
            let _ = std::fs::write(&txt_file, txt_str);

            let md_str = format_md_vault(&payload);
            let _ = std::fs::write(&md_file, md_str);

            println!("\n{} Complete backup created successfully!", "✔".green().bold());
            println!("📂 Folder: {}", target_dir.display().to_string().cyan().bold());
            println!("   🔒 Encrypted Vault : {}", enc_file.display().to_string().green());
            println!("   📄 Raw JSON        : {}", raw_file.display().to_string().yellow());
            println!("   📝 Plaintext       : {}", txt_file.display().to_string().dimmed());
            println!("   📑 Markdown        : {}\n", md_file.display().to_string().dimmed());
        }

        Commands::Import { file } => {
            let abs_file = resolve_destination_path(&file);
            if !abs_file.exists() {
                eprintln!("{}: File '{}' not found.", "Error".red().bold(), abs_file.display());
                return;
            }

            let file_bytes = match std::fs::read(&abs_file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}: Failed to read file: {}", "Error".red().bold(), e);
                    return;
                }
            };

            let mut imported_payload: Option<VaultPayload> = None;

            if file_bytes.len() >= 4 && &file_bytes[..4] == b"PK\x03\x04" {
                match read_vault_archive(&abs_file) {
                    Ok((salt_hex, enc_bytes)) => {
                        println!("Detected encrypted .vault archive: {}", abs_file.file_name().unwrap_or_default().to_string_lossy().cyan());
                        let mut pass = prompt_password("Enter Master Password for this backup: ");
                        if let Ok(salt_bytes) = hex::decode(&salt_hex) {
                            match crypto::decrypt_vault_dual_kdf(pass.as_bytes(), &salt_bytes, &enc_bytes) {
                                Ok((plain, _, _)) => {
                                    pass.zeroize();
                                    if let Ok(p) = serde_json::from_slice::<VaultPayload>(&plain) {
                                        imported_payload = Some(p);
                                    } else {
                                        eprintln!("{}: Failed to parse decrypted payload as JSON.", "Error".red().bold());
                                        return;
                                    }
                                }
                                Err(_) => {
                                    pass.zeroize();
                                    eprintln!("{}: Incorrect master password for backup file.", "Error".red().bold());
                                    return;
                                }
                            }
                        } else {
                            pass.zeroize();
                            eprintln!("{}: Invalid salt in backup archive.", "Error".red().bold());
                            return;
                        }
                    }
                    Err(e) => {
                        eprintln!("{}: Failed to read zip archive: {}", "Error".red().bold(), e);
                        return;
                    }
                }
            } else if file_bytes.len() >= 20 && &file_bytes[..4] == b"MVE1" {
                let salt = &file_bytes[4..20];
                let enc_bytes = &file_bytes[20..];
                println!("Detected encrypted standalone backup: {}", abs_file.file_name().unwrap_or_default().to_string_lossy().cyan());
                let mut pass = prompt_password("Enter Master Password for this backup: ");
                match crypto::decrypt_vault_dual_kdf(pass.as_bytes(), salt, enc_bytes) {
                    Ok((plain, _, _)) => {
                        pass.zeroize();
                        if let Ok(p) = serde_json::from_slice::<VaultPayload>(&plain) {
                            imported_payload = Some(p);
                        } else {
                            eprintln!("{}: Failed to parse decrypted payload as JSON.", "Error".red().bold());
                            return;
                        }
                    }
                    Err(_) => {
                        pass.zeroize();
                        eprintln!("{}: Incorrect master password for backup file.", "Error".red().bold());
                        return;
                    }
                }
            } else if abs_file.extension().and_then(|x| x.to_str()) == Some("enc") && abs_file.with_extension("salt").exists() {
                println!("Detected raw .enc with companion .salt: {}", abs_file.file_name().unwrap_or_default().to_string_lossy().cyan());
                let salt_hex = std::fs::read_to_string(abs_file.with_extension("salt")).unwrap_or_default();
                if let Ok(salt_bytes) = hex::decode(salt_hex.trim()) {
                    let mut pass = prompt_password("Enter Master Password for this backup: ");
                    match crypto::decrypt_vault_dual_kdf(pass.as_bytes(), &salt_bytes, &file_bytes) {
                        Ok((plain, _, _)) => {
                            pass.zeroize();
                            if let Ok(p) = serde_json::from_slice::<VaultPayload>(&plain) {
                                imported_payload = Some(p);
                            }
                        }
                        Err(_) => {
                            pass.zeroize();
                            eprintln!("{}: Incorrect master password for backup file.", "Error".red().bold());
                            return;
                        }
                    }
                }
            } else if let Ok(content) = std::str::from_utf8(&file_bytes) {
                if content.trim_start().starts_with('{') {
                    if let Ok(raw_json) = serde_json::from_str::<serde_json::Value>(content) {
                        let mut p = VaultPayload::default();
                        if let Some(vault_obj) = raw_json.get("vault").and_then(|v| v.as_object()) {
                            for (k, v) in vault_obj {
                                if let Ok(entry) = serde_json::from_value::<VaultEntry>(v.clone()) {
                                    p.vault.insert(k.clone(), entry);
                                }
                            }
                        } else if let Some(vault_obj) = raw_json.as_object() {
                            for (k, v) in vault_obj {
                                if let Ok(entry) = serde_json::from_value::<VaultEntry>(v.clone()) {
                                    p.vault.insert(k.clone(), entry);
                                }
                            }
                        }
                        if let Some(backups_obj) = raw_json.get("backups").and_then(|b| b.as_object()) {
                            for (k, v) in backups_obj {
                                if let Ok(codes) = serde_json::from_value::<Vec<String>>(v.clone()) {
                                    p.backups.insert(k.clone(), codes);
                                }
                            }
                        }
                        imported_payload = Some(p);
                    }
                } else if content.starts_with("folder,") || content.contains(",favorite,type,") {
                    let mut p = VaultPayload::default();
                    let lines: Vec<&str> = content.lines().collect();
                    for line in lines.iter().skip(1) {
                        let cols: Vec<&str> = line.split(',').collect();
                        if cols.len() >= 10 {
                            let folder = cols[0].trim_matches('"');
                            let name = cols[3].trim_matches('"');
                            let username = cols[8].trim_matches('"');
                            let password = cols[9].trim_matches('"');
                            let totp = if cols.len() >= 11 { cols[10].trim_matches('"') } else { "" };
                            if !name.is_empty() {
                                let mut entry = VaultEntry::default();
                                entry.email = username.to_string();
                                entry.password = password.to_string();
                                entry.section = folder.to_string();
                                entry.totp_secret = totp.to_string();
                                p.vault.insert(name.to_string(), entry);
                            }
                        }
                    }
                    imported_payload = Some(p);
                }
            }

            let Some(mut new_data) = imported_payload else {
                eprintln!("{}: Unsupported or unrecognizable file format for '{}'.", "Error".red().bold(), abs_file.display());
                return;
            };

            let (mut payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let mut count = 0;
            for (k, v) in new_data.vault.drain() {
                payload.vault.insert(k, v);
                count += 1;
            }
            for (k, v) in new_data.backups.drain() {
                payload.backups.insert(k, v);
            }

            if let Err(e) = save_vault_and_sync(&vault_path, &salt_path, key.as_ref(), &payload).await {
                eprintln!("{}: {}", "Failed to save imported vault".red().bold(), e);
                return;
            }

            println!(
                "{} Successfully imported and merged {} accounts into your vault!",
                "✔".green().bold(),
                count.to_string().cyan()
            );
        }

        Commands::Export { md, txt, csv, json, vault } => {
            if md.is_none() && txt.is_none() && csv.is_none() && json.is_none() && vault.is_none() {
                println!(
                    "{}",
                    "Please specify at least one export format: --vault, --json, --txt, --csv, or --md".yellow()
                );
                return;
            }

            let (payload, key) = match get_unlocked_vault(&vault_path, &salt_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if let Some(p) = vault {
                let abs = resolve_destination_path(&p);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let raw_json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
                let enc_bytes = match crypto::encrypt_vault_data(key.as_ref(), &raw_json_bytes) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("{}: Failed to encrypt vault: {}", "Error".red().bold(), e);
                        return;
                    }
                };
                let salt_bytes = get_or_create_salt(&salt_path);
                let salt_hex = hex::encode(&salt_bytes);

                if abs.extension().and_then(|x| x.to_str()) == Some("enc") {
                    let mut out = Vec::with_capacity(4 + SALT_LEN + enc_bytes.len());
                    out.extend_from_slice(b"MVE1");
                    out.extend_from_slice(&salt_bytes);
                    out.extend_from_slice(&enc_bytes);
                    if let Err(e) = std::fs::write(&abs, out) {
                        eprintln!("{}: Failed to write {}: {}", "Error".red().bold(), abs.display(), e);
                        return;
                    }
                    let salt_file = abs.with_extension("salt");
                    let _ = std::fs::write(&salt_file, &salt_hex);
                } else {
                    if let Err(e) = create_vault_archive(&abs, &salt_hex, &enc_bytes) {
                        eprintln!("{}: Failed to write {}: {}", "Error".red().bold(), abs.display(), e);
                        return;
                    }
                }
                println!("{} Exported Encrypted Vault to {}", "✔".green().bold(), abs.display().to_string().cyan());
            }

            if let Some(p) = json {
                let abs = resolve_destination_path(&p);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let out = serde_json::to_string_pretty(&payload).unwrap_or_default();
                let _ = std::fs::write(&abs, out);
                println!("{} Exported JSON to {}", "✔".green().bold(), abs.display().to_string().cyan());
            }

            if let Some(p) = txt {
                let abs = resolve_destination_path(&p);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let out = format_txt_vault(&payload);
                let _ = std::fs::write(&abs, out);
                println!("{} Exported TXT to {}", "✔".green().bold(), abs.display().to_string().cyan());
            }

            if let Some(p) = md {
                let abs = resolve_destination_path(&p);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let out = format_md_vault(&payload);
                let _ = std::fs::write(&abs, out);
                println!("{} Exported Markdown to {}", "✔".green().bold(), abs.display().to_string().cyan());
            }

            if let Some(p) = csv {
                let abs = resolve_destination_path(&p);
                if let Some(parent) = abs.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let out = format_csv_vault(&payload);
                let _ = std::fs::write(&abs, out);
                println!("{} Exported CSV to {}", "✔".green().bold(), abs.display().to_string().cyan());
            }
        }
    }
}

fn chrono_lite_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

fn chrono_lite_date() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let z = (now / 86400) as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 142401) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let secs_of_day = now % 86400;
    let h = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    format!("{:04}-{:02}-{:02}_{:02}{:02}", y, m, d, h, min)
}

