use std::fs::File;
use std::io::{Read, Write};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use blake3::Hasher;
use rand::Rng;
use rayon::prelude::*;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    WalkDir(#[from] walkdir::Error),
    #[error("AES encryption error")]
    Aes(aes_gcm::Error),
}

pub fn derive_key(password: &str, salt: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(salt);
    hasher.update(password.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize_xof().fill(&mut output);
    output.to_vec()
}

pub fn encrypt_folder(folder_path: &str, password: &str) -> Result<(), EncryptionError> {
    let salt: [u8; 32] = rand::thread_rng().gen();
    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut metadata_file = File::create(format!("{}/encryption_metadata", folder_path))?;
    metadata_file.write_all(&salt)?;

    WalkDir::new(folder_path)
        .into_iter()
        .par_bridge()
        .try_for_each(|entry| -> Result<(), EncryptionError> {
            let entry = entry?;
            if entry.file_type().is_file()
                && entry.path().file_name() != Some(std::ffi::OsStr::new("encryption_metadata"))
            {
                let path = entry.path();
                let mut contents = Vec::new();
                File::open(entry.path())?.read_to_end(&mut contents)?;

                let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
                let nonce = Nonce::from_slice(&nonce_bytes);

                let encrypted = cipher
                    .encrypt(nonce, contents.as_ref())
                    .map_err(EncryptionError::Aes)?;

                let encrypted_path = path.with_extension(format!(
                    "{}.encrypted",
                    path.extension().and_then(|e| e.to_str()).unwrap_or("")
                ));

                let mut file = File::create(&encrypted_path)?;
                file.write_all(&nonce_bytes)?;
                file.write_all(&encrypted)?;

                std::fs::remove_file(path)?;
            }
            Ok(())
        })?;
    Ok(())
}

pub fn decrypt_folder(folder_path: &str, password: &str) -> Result<(), EncryptionError> {
    let mut salt = [0u8; 32];
    let metadata_path = format!("{}/encryption_metadata", folder_path);
    let mut metadata_file = File::open(&metadata_path)?;
    metadata_file.read_exact(&mut salt)?;

    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    WalkDir::new(folder_path)
        .into_iter()
        .par_bridge()
        .try_for_each(|entry| -> Result<(), EncryptionError> {
            let entry = entry?;
            if entry.file_type().is_file()
                && entry.path().extension() == Some(std::ffi::OsStr::new("encrypted"))
            {
                let path = entry.path();
                let mut file = File::open(entry.path())?;

                let mut nonce_bytes = [0u8; 12];
                file.read_exact(&mut nonce_bytes)?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let mut encrypted = Vec::new();
                file.read_to_end(&mut encrypted)?;

                let decrypted = cipher
                    .decrypt(nonce, encrypted.as_ref())
                    .map_err(EncryptionError::Aes)?;

                let original_ext = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let decrypted_path = path.with_file_name(original_ext);

                File::create(&decrypted_path)?.write_all(&decrypted)?;

                std::fs::remove_file(path)?;
            }
            Ok(())
        })?;

    std::fs::remove_file(metadata_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn create_test_files(dir: &Path) -> std::io::Result<()> {
        fs::write(dir.join("test1.txt"), b"Hello, World!")?;
        fs::write(dir.join("test2.txt"), b"Another test file")?;
        fs::create_dir(dir.join("subdir"))?;
        fs::write(dir.join("subdir/test3.txt"), b"File in subdirectory")?;
        Ok(())
    }

    #[test]
    fn test_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        create_test_files(temp_path)?;

        let password = "test_password123";

        encrypt_folder(temp_path.to_str().unwrap(), password)?;

        assert!(!Path::new(&temp_path.join("test1.txt")).exists());
        assert!(Path::new(&temp_path.join("test1.txt.encrypted")).exists());
        assert!(Path::new(&temp_path.join("encryption_metadata")).exists());

        decrypt_folder(temp_path.to_str().unwrap(), password)?;

        assert_eq!(
            fs::read_to_string(temp_path.join("test1.txt"))?,
            "Hello, World!"
        );
        assert_eq!(
            fs::read_to_string(temp_path.join("test2.txt"))?,
            "Another test file"
        );
        assert_eq!(
            fs::read_to_string(temp_path.join("subdir/test3.txt"))?,
            "File in subdirectory"
        );

        assert!(!Path::new(&temp_path.join("encryption_metadata")).exists());

        Ok(())
    }

    #[test]
    fn test_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        create_test_files(temp_path)?;

        encrypt_folder(temp_path.to_str().unwrap(), "correct_password")?;

        let result = decrypt_folder(temp_path.to_str().unwrap(), "wrong_password");

        assert!(result.is_err());
        Ok(())
    }
}
