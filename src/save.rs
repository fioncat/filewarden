use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64Engine;
use base64::Engine;

use crate::aes;

#[derive(Debug, Default)]
pub struct Save {
    path: PathBuf,
    data: HashMap<String, [u8; 32]>,
}

impl Save {
    pub fn load(path: &Path) -> Result<Self> {
        let save_data = match fs::read_to_string(path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: PathBuf::from(path),
                    data: HashMap::new(),
                });
            }
            Err(e) => return Err(e).context("read save data"),
        };
        let lines = save_data.lines();
        let mut data = HashMap::new();
        for line in lines {
            let fields = line.split(' ').collect::<Vec<_>>();
            if fields.len() != 2 {
                continue;
            }
            let name = fields[0];
            if name.is_empty() {
                continue;
            }
            let key = B64Engine
                .decode(fields[1].as_bytes())
                .with_context(|| format!("decode key of user {}", name))?;
            if key.len() != 32 {
                continue;
            }
            let mut key_array = [0; 32];
            for (i, byte) in key.iter().enumerate() {
                key_array[i] = *byte;
            }
            data.insert(name.to_string(), key_array);
        }

        Ok(Self {
            path: PathBuf::from(path),
            data,
        })
    }

    pub fn get(&self, name: &str) -> Option<&[u8; 32]> {
        self.data.get(name)
    }

    pub fn get_default_user(&self) -> String {
        if self.data.len() == 1 {
            return self.data.keys().next().unwrap().to_string();
        }
        String::new()
    }

    pub fn insert(&mut self, user: &str, password: &str) {
        let key = aes::generate_key(user, password);
        self.data.insert(user.to_string(), key);
    }

    pub fn delete(&mut self, name: &str) -> bool {
        self.data.remove(name).is_some()
    }

    pub fn save(&self) -> Result<()> {
        if self.data.is_empty() {
            return Ok(());
        }

        let mut lines = Vec::with_capacity(self.data.len());
        for (name, key) in &self.data {
            let key_str = B64Engine.encode(key);
            lines.push(format!("{} {}", name, key_str));
        }
        lines.sort_unstable();

        let save_data = lines.join("\n");
        fs::write(&self.path, save_data).context("write save data")?;

        Ok(())
    }
}
