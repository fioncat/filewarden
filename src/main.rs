mod aes;
mod save;
mod term;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;

use aes::{AesDecryptor, AesEncryptor};
use anyhow::{bail, Context, Result};
use clap::Parser;
use save::Save;
use term::{ProgressReader, StdoutWrap};

#[derive(Parser, Debug)]
#[command(author, version = env!("FWD_VERSION"), about)]
struct FileWardenArgs {
    /// The file to read data. Default will try to read data from stdin.
    /// This can also be a directory, in which case the program will consider all file with
    /// prefix `.` and suffiex `.fwd` as the encrypted file, and others as the plain file.
    /// All of the files will be encrypted or decrypted (depends on `--decrypt` flag).
    input: Option<String>,

    /// Save output to a file
    #[arg(long, short)]
    output: Option<String>,

    /// Decrypt mode, without this flag, the program will encrypt the data.
    #[arg(long, short)]
    decrypt: bool,

    /// Save user and password to local file (~/.fwd) and exit.
    #[arg(long, short)]
    save_password: bool,

    /// Delete user from local file (~/.fwd) and exit.
    #[arg(long, short = 'D')]
    delete_password: bool,

    #[clap(skip)]
    save: Save,

    #[clap(skip)]
    user: String,

    #[clap(skip)]
    keys: HashMap<String, [u8; 32]>,
}

impl FileWardenArgs {
    const SHOW_PROGRESS_BAR_SIZE: u64 = 4096 * 1024;

    fn run(&mut self) -> Result<()> {
        let home_dir = match dirs::home_dir() {
            Some(dir) => dir,
            None => bail!("cannot find home directory"),
        };
        let save_file = home_dir.join(".fwd");

        self.save = Save::load(&save_file)?;
        if self.save_password {
            let user = term::input_user()?;
            let password = term::input_password(&user, true)?;
            self.save.insert(&user, &password);
            self.save.save()?;
            eprintln!("User {user:?} saved");
            return Ok(());
        }

        if self.delete_password {
            let user = term::input_user()?;
            if !self.save.delete(&user) {
                bail!("cannot find user {user:?}");
            }
            self.save.save()?;
            eprintln!("User {user:?} deleted");
            return Ok(());
        }
        self.user = self.save.get_default_user();

        if let Some(ref input) = self.input {
            let path = PathBuf::from(input);
            let meta = path.metadata()?;
            if meta.is_dir() {
                return self.handle_dir(&path);
            }
        }

        let input = self.input.clone();
        let output = self.output.clone();
        self.handle(&input, &output)
    }

    fn handle_dir(&mut self, dir: &Path) -> Result<()> {
        let ignore_path = dir.join(".fwdignore");
        let ignore_data = match fs::read_to_string(&ignore_path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).context("read ignore file"),
        };
        let ignore_set = ignore_data
            .lines()
            .map(|line| line.trim().to_string())
            .collect::<HashSet<_>>();

        let dir = PathBuf::from(dir);
        for ent in fs::read_dir(&dir)? {
            let ent = ent?;
            let meta = ent.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let name = match ent.file_name().to_str() {
                Some(name) => name.to_string(),
                None => continue,
            };
            if name == ".fwdignore" {
                continue;
            }
            if self.decrypt {
                let raw_name = match name.strip_suffix(".fwd") {
                    Some(name) => name,
                    None => continue,
                };
                let input = format!("{}", dir.join(&name).display());
                let output = format!("{}", dir.join(raw_name).display());
                eprintln!("Decrypting {name:?} to {raw_name:?}");

                self.handle(&Some(input), &Some(output))
                    .with_context(|| format!("failed to decrypt {name:?}"))?;
                continue;
            }

            if name.ends_with(".fwd") {
                continue;
            }
            if ignore_set.contains(&name) {
                continue;
            }
            let dest_name = format!("{name}.fwd");
            let input = format!("{}", dir.join(&name).display());
            let output = format!("{}", dir.join(&dest_name).display());
            eprintln!("Encrypting {name:?} to {dest_name:?}");
            self.handle(&Some(input), &Some(output))
                .with_context(|| format!("failed to encrypt {name:?}"))?;
        }

        Ok(())
    }

    fn handle(&mut self, input: &Option<String>, output: &Option<String>) -> Result<()> {
        let mut input_meta = None;
        let mut source: Box<dyn Read> = match input {
            Some(input) => {
                let file = File::open(input).context("open input file")?;
                let meta = file.metadata().context("get input file metadata")?;
                input_meta = Some(meta);
                Box::new(file)
            }
            None => Box::new(io::stdin()),
        };

        let mut is_dest_file = false;
        let dest: Box<dyn Write> = match output {
            Some(output) => {
                match File::open(output) {
                    Ok(dest_file) => {
                        // Source and destination files cannot be the same; otherwise,
                        // it may cause the program to hang (reading data and writing to
                        // the same file, resulting in an endless loop). Therefore, a
                        // precautionary measure needs to be taken here.
                        // TODO: The logic here uses the UNIX file system's INO for
                        // checking. If porting to Windows, the logic in this part
                        // needs to be modified.
                        if let Some(ref src_meta) = input_meta {
                            let dest_meta =
                                dest_file.metadata().context("get output file metadata")?;
                            if src_meta.ino() == dest_meta.ino() {
                                bail!("the dest file and src file can't be same");
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).context("open output file"),
                }

                is_dest_file = true;
                let dest = File::create(output).context("create dest file")?;
                Box::new(dest)
            }
            None => {
                let stdout = io::stdout();
                if termion::is_tty(&stdout) {
                    Box::new(StdoutWrap { stdout })
                } else {
                    is_dest_file = true;
                    Box::new(stdout)
                }
            }
        };

        if let Some(src_meta) = input_meta {
            let src_size = src_meta.len();
            if is_dest_file && src_size > Self::SHOW_PROGRESS_BAR_SIZE {
                // The progress bar for encryption/decryption will only be displayed in the
                // terminal if writing to a file and the source file is large enough.
                source = Box::new(ProgressReader::new(
                    "Processing",
                    "Process",
                    src_size as usize,
                    source,
                ));
            }
        }

        if self.decrypt {
            let decryptor = AesDecryptor::load(source, dest)?;
            let key = self.get_key(decryptor.user())?;
            return decryptor.run(key);
        }

        let encryptor = AesEncryptor::load(source, dest);
        if self.user.is_empty() {
            self.user = term::input_user()?;
        }
        let user = self.user.clone();
        let key = self.get_key(&user)?;

        encryptor.run(&self.user, key)
    }

    fn get_key(&mut self, user: &str) -> Result<[u8; 32]> {
        match self.save.get(user) {
            Some(key) => Ok(*key),
            None => match self.keys.get(user) {
                Some(key) => Ok(*key),
                None => {
                    let password = term::input_password(user, true)?;
                    let key = aes::generate_key(user, &password);
                    self.keys.insert(user.to_string(), key);
                    Ok(key)
                }
            },
        }
    }
}

fn main() {
    let mut args = FileWardenArgs::parse();

    if let Err(e) = args.run() {
        eprintln!("Error: {:#}", e);
        process::exit(1);
    }
}
