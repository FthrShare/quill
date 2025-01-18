use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use blake3::Hasher;
use futures::stream::{self, StreamExt};
use rand::Rng;
use thiserror::Error;
use tokio::fs::{remove_file, write, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub struct EncryptionTask {
    path: String,
    key: Key<Aes256Gcm>,
    salt: [u8; 32],
}

fn derive_key(password: &str, salt: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(salt);
    hasher.update(password.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize_xof().fill(&mut output);
    output.to_vec()
}

async fn construct_key(
    password: &str,
    path: Option<String>,
) -> Result<(Key<Aes256Gcm>, [u8; 32]), EncryptionError> {
    let salt: [u8; 32] = match path {
        Some(file_path) => {
            let mut file = File::open(file_path).await?;
            let mut salt = [0u8; 32];
            file.read_exact(&mut salt).await?;
            salt
        }
        None => rand::thread_rng().gen(),
    };
    let key_bytes = derive_key(password, &salt);
    Ok((Key::<Aes256Gcm>::from_slice(&key_bytes).to_owned(), salt))
}

pub async fn encrypt(
    path: &str,
    password: &str,
    concurrency_limit: Option<usize>,
) -> Result<(), EncryptionError> {
    let sys_path = Path::new(path);
    if !sys_path.exists() {
        return Err(EncryptionError::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Path does not exist",
        )));
    }

    let (key, salt) = construct_key(password, None).await?;
    let task = EncryptionTask {
        path: path.to_string(),
        key,
        salt,
    };

    if sys_path.is_dir() {
        let limit = concurrency_limit.unwrap_or(100);
        encrypt_folder(task, limit).await
    } else {
        encrypt_file(task).await
    }
}

pub async fn encrypt_file(task: EncryptionTask) -> Result<(), EncryptionError> {
    let cipher = Aes256Gcm::new(&task.key);
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut file = File::open(&task.path).await?;
    let metadata = file.metadata().await?;
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents).await?;

    let encrypted = cipher
        .encrypt(nonce, contents.as_ref())
        .map_err(EncryptionError::Aes)?;

    let encrypted_path = format!("{}.encrypted", task.path);

    let mut file = File::create(&encrypted_path).await?;
    file.write_all(&task.salt).await?;
    file.write_all(&nonce_bytes).await?;
    file.write_all(&encrypted).await?;

    remove_file(task.path).await?;
    Ok(())
}

pub async fn encrypt_folder(
    dir_task: EncryptionTask,
    concurrency_limit: usize,
) -> Result<(), EncryptionError> {
    let mut tasks = Vec::new();

    for entry in WalkDir::new(&dir_task.path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file()
            && entry.path().file_name() != Some(std::ffi::OsStr::new("encryption_metadata"))
        {
            let path = entry.path().to_str().unwrap().to_string();
            tasks.push(EncryptionTask {
                path,
                key: dir_task.key,
                salt: dir_task.salt,
            });
        }
    }

    stream::iter(tasks)
        .map(encrypt_file)
        .buffer_unordered(concurrency_limit)
        .collect::<Vec<_>>()
        .await;

    Ok(())
}

pub async fn decrypt(
    path: &str,
    password: &str,
    concurrency_limit: Option<usize>,
) -> Result<(), EncryptionError> {
    let sys_path = Path::new(path);
    if !sys_path.exists() {
        return Err(EncryptionError::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Path does not exist",
        )));
    }

    let is_dir = sys_path.is_dir();

    let salt_path = if is_dir {
        let first_file = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_type().is_file()
                    && e.path().extension() == Some(std::ffi::OsStr::new("encrypted"))
            })
            .ok_or_else(|| {
                EncryptionError::IO(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No encrypted files found in directory",
                ))
            })?;
        first_file.path().to_str().unwrap().to_string()
    } else {
        path.to_owned()
    };

    let (key, salt) = construct_key(password, Some(salt_path)).await?;
    let task = EncryptionTask {
        path: path.to_string(),
        key,
        salt,
    };

    if is_dir {
        let limit = concurrency_limit.unwrap_or(100);
        decrypt_folder(task, limit).await
    } else {
        decrypt_file(task).await
    }
}

pub async fn decrypt_file(task: EncryptionTask) -> Result<(), EncryptionError> {
    let cipher = Aes256Gcm::new(&task.key);

    let mut file = File::open(&task.path).await?;
    let metadata = file.metadata().await?;
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    let mut encrypted = Vec::with_capacity(metadata.len() as usize - 44); // 32 (salt) + 12 (nonce)

    file.read_exact(&mut salt).await?;
    file.read_exact(&mut nonce_bytes).await?;
    file.read_to_end(&mut encrypted).await?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher
        .decrypt(nonce, encrypted.as_ref())
        .map_err(EncryptionError::Aes)?;

    let decrypted_path = task.path.replace(".encrypted", "");
    write(&decrypted_path, &decrypted).await?;
    remove_file(&task.path).await?;

    Ok(())
}

pub async fn decrypt_folder(
    dir_task: EncryptionTask,
    concurrency_limit: usize,
) -> Result<(), EncryptionError> {
    let mut tasks = Vec::new();

    for entry in WalkDir::new(&dir_task.path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file()
            && entry.path().extension() == Some(std::ffi::OsStr::new("encrypted"))
        {
            let path = entry.path().to_str().unwrap().to_string();
            tasks.push(EncryptionTask {
                path,
                key: dir_task.key,
                salt: dir_task.salt,
            });
        }
    }

    stream::iter(tasks)
        .map(decrypt_file)
        .buffer_unordered(concurrency_limit)
        .collect::<Vec<_>>()
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{tempdir, NamedTempFile};

    #[tokio::test]
    async fn test_single_file_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_str().unwrap();

        fs::write(path, b"test data")?;

        encrypt(path, "password123", None).await?;

        let encrypted_path = format!("{}.encrypted", path);
        assert!(Path::new(&encrypted_path).exists());
        assert!(!Path::new(path).exists());

        decrypt(&encrypted_path, "password123", None).await?;

        let decrypted_content = fs::read_to_string(path)?;
        assert_eq!(decrypted_content, "test data");

        Ok(())
    }

    #[tokio::test]
    async fn test_folder_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let dir_path = temp_dir.path();

        fs::write(dir_path.join("file1.txt"), b"content1")?;
        fs::write(dir_path.join("file2.txt"), b"content2")?;

        encrypt(dir_path.to_str().unwrap(), "password123", None).await?;

        assert!(Path::new(&dir_path.join("file1.txt.encrypted")).exists());
        assert!(Path::new(&dir_path.join("file2.txt.encrypted")).exists());

        decrypt(dir_path.to_str().unwrap(), "password123", None).await?;

        assert_eq!(fs::read_to_string(dir_path.join("file1.txt"))?, "content1");
        assert_eq!(fs::read_to_string(dir_path.join("file2.txt"))?, "content2");

        Ok(())
    }

    #[tokio::test]
    async fn test_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_str().unwrap();

        fs::write(path, b"test data")?;
        encrypt(path, "password123", None).await?;

        let encrypted_path = format!("{}.encrypted", path);
        let result = decrypt(&encrypted_path, "wrongpassword", None).await;

        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_path() {
        let result = encrypt("/nonexistent/path", "password123", None).await;
        assert!(result.is_err());
    }
}
