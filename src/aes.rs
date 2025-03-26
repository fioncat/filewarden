use std::io::{BufRead, BufReader, Read, Write};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64Engine;
use base64::Engine;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

const ENCRYPT_READ_BUFFER_SIZE: usize = 4096;

const SALT_LENGTH: usize = 5;
const NONCE_LENGTH: usize = 12;
const HEADER_LENGTH: usize = SALT_LENGTH + NONCE_LENGTH;

const PBKDF2_ROUNDS: u32 = 600_000;

pub fn encrypt<R, W, S>(plain: R, mut dest: W, password: S) -> Result<()>
where
    R: Read,
    W: Write,
    S: AsRef<str>,
{
    let mut reader = BufReader::new(plain);
    let mut buffer = [0; ENCRYPT_READ_BUFFER_SIZE];

    let mut write_data = |data: &[u8]| -> Result<()> {
        dest.write_all(data).context("write data to dest")?;
        dest.write(b"\n").context("write break to dest")?;
        dest.flush().context("flush dest")?;
        Ok(())
    };

    // Generate salt.
    let mut salt: [u8; SALT_LENGTH] = [0; SALT_LENGTH];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);

    // Use PBKDF2 to generate private key according to user password and generated
    // salt. This approach ensures that the generated key is robust enough, and the
    // original password is less likely to be easily exposed.
    let key = pbkdf2_hmac_array::<Sha256, 32>(password.as_ref().as_bytes(), &salt, PBKDF2_ROUNDS);
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key);
    // Generate the nonce in aes-256-gcm.
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    assert_eq!(nonce.len(), NONCE_LENGTH);

    // Write salt and nonce into file header.
    let mut head = salt.to_vec();
    head.extend(nonce.to_vec());
    let head_b64 = B64Engine.encode(head);
    write_data(&head_b64.into_bytes())?;

    loop {
        // Encrypts 4096 bytes of data from the source file at a time and writes it
        // as one line to the destination file.
        // The reason for encrypting in batches is to prevent the program from
        // consuming excessive memory by loading the entire source data into memory,
        // especially when the source file is large.
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let data = &buffer[..bytes_read];
                let encrypted = match cipher.encrypt(&nonce, data) {
                    Ok(data) => data,
                    Err(err) => bail!("use aes256gcm to encrypt data: {err}"),
                };
                let line = B64Engine.encode(encrypted);
                write_data(&line.into_bytes())?;
            }
            Err(err) => return Err(err).context("read plain data"),
        }
    }

    Ok(())
}

pub fn decrypt<R, W, S>(encrypted: R, mut dest: W, password: S) -> Result<()>
where
    R: Read,
    W: Write,
    S: AsRef<str>,
{
    let reader = BufReader::new(encrypted);
    let mut lines = reader.lines();
    let mut must_read_line = || -> Result<String> {
        match lines.next() {
            Some(line) => line.context("read data from file"),
            None => bail!("unexpected end of the file, the file is too short"),
        }
    };

    let head = B64Engine
        .decode(must_read_line()?)
        .context("decode header as base64 string")?;
    if head.len() != HEADER_LENGTH {
        bail!(
            "invalid header length, expect {}, found {}",
            HEADER_LENGTH,
            head.len()
        );
    }

    let salt = &head[..SALT_LENGTH];
    let nonce = &head[SALT_LENGTH..];

    let key = pbkdf2_hmac_array::<Sha256, 32>(password.as_ref().as_bytes(), salt, PBKDF2_ROUNDS);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::<Aes256Gcm>::from_slice(nonce);

    for line in lines {
        // During decryption, each line represents a batch, and each batch of data
        // is decrypted one at a time.
        let line = line.context("read content from file")?;
        let buffer = B64Engine
            .decode(line)
            .context("decode content as base64 string")?;
        let buffer: &[u8] = &buffer;
        let plain = match cipher.decrypt(nonce, buffer) {
            Ok(data) => data,
            Err(_) => bail!("decrypt failed, incorrect password or content"),
        };
        dest.write_all(&plain).context("write buffer to dest")?;
        dest.flush().context("flush dest")?;
    }

    Ok(())
}
