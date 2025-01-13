use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use blake3::Hasher;
use rand::Rng;
use rayon::prelude::*;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    WalkDir(#[from] walkdir::Error),
    #[error("AES encryption error")]
    Aes(aes_gcm::Error),
    #[error(transparent)]
    TokioJoin(#[from] tokio::task::JoinError),
    #[error("Invalid salt")]
    InvalidSalt,
}

fn derive_key(password: &str, salt: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(salt);
    hasher.update(password.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize_xof().fill(&mut output);
    output.to_vec()
}

pub async fn encrypt(path: &str, password: &str) -> Result<(), EncryptionError> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(EncryptionError::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Path does not exist",
        )));
    }

    if path.is_dir() {
        encrypt_folder(path.to_str().unwrap(), password).await
    } else {
        encrypt_file(path.to_str().unwrap(), password).await
    }
}

pub async fn decrypt(path: &str, password: &str) -> Result<(), EncryptionError> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(EncryptionError::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Path does not exist",
        )));
    }

    if path.is_dir() {
        decrypt_folder(path.to_str().unwrap(), password).await
    } else {
        decrypt_file(path.to_str().unwrap(), password).await
    }
}

pub async fn encrypt_file(file_path: &str, password: &str) -> Result<(), EncryptionError> {
    let salt: [u8; 32] = rand::thread_rng().gen();
    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();

    let file_path_owned = file_path.to_string();
    let encrypted = tokio::task::spawn_blocking(move || -> Result<_, EncryptionError> {
        let mut file = File::open(&file_path_owned)?;
        let metadata = file.metadata()?;
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut contents)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .encrypt(nonce, contents.as_ref())
            .map_err(EncryptionError::Aes)
    })
    .await??;

    let (encrypted_path, metadata_path) = (
        format!("{}.encrypted", file_path),
        format!("{}.metadata", file_path),
    );

    let (meta_result, file_result) = tokio::join!(tokio::fs::write(&metadata_path, &salt), async {
        let mut file = tokio::fs::File::create(&encrypted_path).await?;
        file.write_all(&nonce_bytes).await?;
        file.write_all(&encrypted).await
    });

    meta_result?;
    file_result?;
    tokio::fs::remove_file(file_path).await?;
    Ok(())
}

pub async fn encrypt_folder(folder_path: &str, password: &str) -> Result<(), EncryptionError> {
    let salt: [u8; 32] = rand::thread_rng().gen();
    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Arc::new(Aes256Gcm::new(key));

    let metadata_path = format!("{}/encryption_metadata", folder_path);
    tokio::fs::write(&metadata_path, &salt).await?;

    WalkDir::new(folder_path)
        .into_iter()
        .par_bridge()
        .try_for_each(|entry| -> Result<(), EncryptionError> {
            let entry = entry?;
            if !entry.file_type().is_file()
                || entry.path().file_name() == Some(std::ffi::OsStr::new("encryption_metadata"))
            {
                return Ok(());
            }

            let path = entry.path().to_owned();
            let cipher = Arc::clone(&cipher);

            tokio::task::block_in_place(|| {
                let mut file = BufReader::new(File::open(&path)?);
                let mut contents = Vec::with_capacity(file.get_ref().metadata()?.len() as usize);
                file.read_to_end(&mut contents)?;

                let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
                let nonce = Nonce::from_slice(&nonce_bytes);

                let encrypted = cipher
                    .encrypt(nonce, contents.as_ref())
                    .map_err(EncryptionError::Aes)?;

                let encrypted_path = path.with_extension(format!(
                    "{}.encrypted",
                    path.extension().and_then(|e| e.to_str()).unwrap_or("")
                ));

                let mut writer = BufWriter::new(File::create(&encrypted_path)?);
                writer.write_all(&nonce_bytes)?;
                writer.write_all(&encrypted)?;
                writer.flush()?;

                std::fs::remove_file(&path)?;
                Ok(())
            })
        })?;

    Ok(())
}

pub async fn decrypt_file(file_path: &str, password: &str) -> Result<(), EncryptionError> {
    let metadata_path = file_path.replace(".encrypted", ".metadata");

    let salt = tokio::fs::read(&metadata_path).await?;
    if salt.len() != 32 {
        return Err(EncryptionError::InvalidSalt);
    }
    let salt = salt[..32].try_into().unwrap();

    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let file_path_owned = file_path.to_string();
    let decrypted = tokio::task::spawn_blocking(move || -> Result<_, EncryptionError> {
        let mut file = File::open(&file_path_owned)?;

        let mut nonce_bytes = [0u8; 12];
        file.read_exact(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let metadata = file.metadata()?;
        let mut encrypted = Vec::with_capacity(metadata.len() as usize - 12); // Subtract nonce size
        file.read_to_end(&mut encrypted)?;

        cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(EncryptionError::Aes)
    })
    .await??;

    let decrypted_path = file_path.replace(".encrypted", "");

    tokio::fs::write(&decrypted_path, &decrypted).await?;

    let (_, _) = tokio::join!(
        tokio::fs::remove_file(file_path),
        tokio::fs::remove_file(metadata_path)
    );

    Ok(())
}

pub async fn decrypt_folder(folder_path: &str, password: &str) -> Result<(), EncryptionError> {
    let metadata_path = format!("{}/encryption_metadata", folder_path);
    let mut metadata_file = BufReader::new(File::open(&metadata_path)?);
    let mut salt = [0u8; 32];
    metadata_file.read_exact(&mut salt)?;

    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Arc::new(Aes256Gcm::new(key));

    WalkDir::new(folder_path)
        .into_iter()
        .par_bridge()
        .try_for_each(|entry| -> Result<(), EncryptionError> {
            let entry = entry?;
            if !entry.file_type().is_file()
                || entry.path().extension() != Some(std::ffi::OsStr::new("encrypted"))
            {
                return Ok(());
            }

            let path = entry.path();
            let cipher = Arc::clone(&cipher);

            tokio::task::block_in_place(|| {
                let mut file = BufReader::new(File::open(path)?);
                let mut nonce_bytes = [0u8; 12];
                file.read_exact(&mut nonce_bytes)?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let mut encrypted = Vec::with_capacity(file.get_ref().metadata()?.len() as usize);
                file.read_to_end(&mut encrypted)?;

                let decrypted = cipher
                    .decrypt(nonce, encrypted.as_ref())
                    .map_err(EncryptionError::Aes)?;

                let original_ext = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let decrypted_path = path.with_file_name(original_ext);

                BufWriter::new(File::create(&decrypted_path)?).write_all(&decrypted)?;

                std::fs::remove_file(path)?;
                Ok(())
            })
        })?;

    tokio::fs::remove_file(metadata_path).await?;
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

    #[tokio::test]
    async fn test_unified_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        let test_file = temp_path.join("test.txt");
        fs::write(&test_file, b"Hello, World!")?;

        encrypt(test_file.to_str().unwrap(), "password123").await?;
        decrypt(
            &format!("{}.encrypted", test_file.to_str().unwrap()),
            "password123",
        )
        .await?;

        assert_eq!(fs::read_to_string(&test_file)?, "Hello, World!");

        create_test_files(temp_path)?;

        encrypt(temp_path.to_str().unwrap(), "password123").await?;
        decrypt(temp_path.to_str().unwrap(), "password123").await?;

        assert_eq!(
            fs::read_to_string(temp_path.join("test1.txt"))?,
            "Hello, World!"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_single_file_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();
        let test_file = temp_path.join("test.txt");

        fs::write(&test_file, b"Hello, World!")?;
        let file_path = test_file.to_str().unwrap();

        let password = "test_password123";

        encrypt_file(file_path, password).await?;

        assert!(!Path::new(file_path).exists());
        assert!(Path::new(&format!("{}.encrypted", file_path)).exists());
        assert!(Path::new(&format!("{}.metadata", file_path)).exists());

        decrypt_file(&format!("{}.encrypted", file_path), password).await?;

        assert_eq!(fs::read_to_string(file_path)?, "Hello, World!");
        assert!(!Path::new(&format!("{}.metadata", file_path)).exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        create_test_files(temp_path)?;

        let password = "test_password123";

        encrypt_folder(temp_path.to_str().unwrap(), password).await?;

        assert!(!Path::new(&temp_path.join("test1.txt")).exists());
        assert!(Path::new(&temp_path.join("test1.txt.encrypted")).exists());
        assert!(Path::new(&temp_path.join("encryption_metadata")).exists());

        decrypt_folder(temp_path.to_str().unwrap(), password).await?;

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

    #[tokio::test]
    async fn test_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        create_test_files(temp_path)?;

        encrypt_folder(temp_path.to_str().unwrap(), "correct_password").await?;

        let result = decrypt_folder(temp_path.to_str().unwrap(), "wrong_password").await;

        assert!(result.is_err());
        Ok(())
    }
}
