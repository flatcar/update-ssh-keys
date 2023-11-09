// Copyright 2017 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! update-ssh-keys library
//!
//! this library provides an interface for manipulating the authorized keys
//! directory. in particular, it provides functionality for
//! * listing authorized keys
//! * adding authorized keys
//! * removing an authorized key by name
//! * disabling an authorized key by name
//!
//! when the authorized keys directory is first opened, a file in the users home
//! directory is locked. This lock is observed by this library and the golang
//! analogue. When the directory is no longer being manipulated, the lock is
//! released. See `AuthorizedKeys::open` for details.

#[macro_use]
extern crate error_chain;
extern crate fs2;
extern crate openssh_keys;
extern crate uzers;

pub mod errors {
    error_chain! {
        links {
        }
        foreign_links {
            Io(::std::io::Error);
            ParseError(::openssh_keys::errors::OpenSSHKeyError);
        }
        errors {
            KeysDisabled(name: String) {
                description("keys are disabled")
                display("keys with name '{}' are disabled", name)
            }
            KeysExist(name: String) {
                description("keys already exist")
                display("keys with name '{}' already exist", name)
            }
            NoKeysFound(ssh_dir: String) {
                description("no keys found")
                display("update-ssh-keys: no keys found in {}", ssh_dir)
            }
        }
    }
}

use errors::*;
use fs2::FileExt;
use openssh_keys::PublicKey;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use uzers::os::unix::UserExt;
use uzers::{switch, User};

const SSH_DIR: &str = ".ssh";
const AUTHORIZED_KEYS_DIR: &str = "authorized_keys.d";
const AUTHORIZED_KEYS_FILE: &str = "authorized_keys";
const PRESERVED_KEYS_FILE: &str = "old_authorized_keys";
const LOCK_FILE: &str = ".authorized_keys.d.lock";
const STAGE_FILE: &str = ".authorized_keys.d.stage_file";
const STAGE_DIR: &str = ".authorized_keys.d.stage_dir";
const STAGE_OLD_DIR: &str = ".authorized_keys.d.old";

fn lock_file(user: &User) -> PathBuf {
    user.home_dir().join(LOCK_FILE)
}

fn default_ssh_dir(user: &User) -> PathBuf {
    user.home_dir().join(SSH_DIR)
}

fn authorized_keys_dir<P: AsRef<Path>>(ssh_dir: P) -> PathBuf {
    ssh_dir.as_ref().join(AUTHORIZED_KEYS_DIR)
}

fn authorized_keys_file<P: AsRef<Path>>(ssh_dir: P) -> PathBuf {
    ssh_dir.as_ref().join(AUTHORIZED_KEYS_FILE)
}

fn stage_dir<P: AsRef<Path>>(ssh_dir: P) -> PathBuf {
    ssh_dir.as_ref().join(STAGE_DIR)
}

fn stage_old_dir<P: AsRef<Path>>(ssh_dir: P) -> PathBuf {
    ssh_dir.as_ref().join(STAGE_OLD_DIR)
}

fn stage_file<P: AsRef<Path>>(ssh_dir: P) -> PathBuf {
    ssh_dir.as_ref().join(STAGE_FILE)
}

fn switch_user(user: &User) -> Result<switch::SwitchUserGuard> {
    switch::switch_user_group(user.uid(), user.primary_group_id())
        .chain_err(|| "failed to switch user/group")
}

#[derive(Debug)]
struct FileLock {
    pub lock: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        self.unlock().unwrap();
    }
}

impl FileLock {
    fn try_new(path: &Path) -> Result<Self> {
        Ok(FileLock {
            lock: File::create(path)
                .chain_err(|| format!("failed to create lock file: {:?}", path))?,
        })
    }

    fn lock(&self) -> Result<()> {
        self.lock
            .lock_exclusive()
            .chain_err(|| "failed to lock file")
    }

    fn unlock(&self) -> Result<()> {
        self.lock.unlock().chain_err(|| "failed to unlock file")
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthorizedKeys {
    pub ssh_dir: PathBuf,
    pub keys: HashMap<String, AuthorizedKeySet>,
    pub user: User,
    lock: FileLock,
}

impl Drop for AuthorizedKeys {
    fn drop(&mut self) {}
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizedKeySet {
    pub filename: String,
    pub disabled: bool,
    pub keys: Vec<AuthorizedKeyEntry>,
}

#[derive(Clone, Debug)]
pub enum AuthorizedKeyEntry {
    Valid { key: PublicKey },
    Invalid { key: String },
}

/// `truncate_dir` empties a directory and resets it's permission to the current
/// umask. If the directory doesn't exists, it creates it. If the path exists
/// but it's a file, it deletes the file and creates a directory there instead.
fn truncate_dir<P: AsRef<Path>>(dir: P) -> Result<()> {
    let dir = dir.as_ref();

    if dir.exists() {
        if dir.is_dir() {
            fs::remove_dir_all(dir)
                .chain_err(|| format!("failed to remove existing directory '{:?}'", dir))?;
        } else if dir.is_file() {
            fs::remove_file(dir)
                .chain_err(|| format!("failed to remove existing file '{:?}'", dir))?;
        } else {
            return Err(format!(
                "failed to remove existing path '{:?}': not a file or directory",
                dir
            )
            .into());
        }
    }

    fs::create_dir_all(dir).chain_err(|| format!("failed to create directory '{:?}'", dir))
}

/// `replace_dir` moves old to new safely.
///
/// It takes the following steps to do so:
/// 1. Truncating stage, in case a stale staging directory is still around.
/// 1. Moving new to stage.
/// 1. Moving old to new.
/// 1. Truncating stage again to clean up.
/// If new doesn't exist, it simply renames old to new. if new is a file, it
/// deletes the file and moves the directory. If old doesn't exist, nothing
/// happens. If old is a file and not a directory, nothing happens.
fn replace_dir<P: AsRef<Path>>(old: P, new: P, stage: P) -> Result<()> {
    let old = old.as_ref();
    let new = new.as_ref();
    let stage = stage.as_ref();

    if old.exists() && old.is_dir() {
        // sync the old directory to ensure our changes have been persisted
        let old_as_file = File::open(old)
            .chain_err(|| format!("failed to open old dir '{}' for syncing", old.display()))?;
        old_as_file
            .sync_all()
            .chain_err(|| format!("failed to sync old dir '{}'", old.display()))?;

        truncate_dir(stage)?;
        if new.exists() {
            fs::rename(new, stage)
                .chain_err(|| format!("failed to move '{:?}' to '{:?}'", new, stage))?;
        }
        fs::rename(old, new).chain_err(|| format!("failed to move '{:?}' to '{:?}'", old, new))?;

        let parent_path = new
            .parent()
            .ok_or_else(|| format!("failed to sync parent directory of '{}'", new.display()))?;
        let parent_dir = File::open(parent_path)
            .chain_err(|| format!("failed to open dir '{}' for syncing", parent_path.display()))?;
        parent_dir
            .sync_all()
            .chain_err(|| format!("failed to sync dir '{}'", parent_path.display()))?;

        truncate_dir(stage)?;
    }

    Ok(())
}

impl AuthorizedKeys {
    pub fn authorized_keys_dir(&self) -> PathBuf {
        authorized_keys_dir(&self.ssh_dir)
    }

    pub fn authorized_keys_file(&self) -> PathBuf {
        authorized_keys_file(&self.ssh_dir)
    }

    pub fn stage_dir(&self) -> PathBuf {
        stage_dir(&self.ssh_dir)
    }

    fn stage_old_dir(&self) -> PathBuf {
        stage_old_dir(&self.ssh_dir)
    }

    pub fn stage_file(&self) -> PathBuf {
        stage_file(&self.ssh_dir)
    }

    /// write writes all authorized_keys.d changes onto disk. it writes the
    /// current state to a staging directory and then moves that staging
    /// directory to the authorized_keys.d path.
    pub fn write(&self) -> Result<()> {
        // switch users
        let _guard = switch_user(&self.user)?;

        // get our staging directory
        let stage_dir = self.stage_dir();
        truncate_dir(&stage_dir).chain_err(|| {
            format!(
                "failed to create staging directory '{}'",
                stage_dir.display()
            )
        })?;

        // write all the keys to the staging directory
        for keyset in self.keys.values() {
            let keyfilename = stage_dir.join(&keyset.filename);
            let mut keyfile = File::create(&keyfilename)
                .chain_err(|| format!("failed to create file '{:?}'", keyfilename))?;
            // if the keyset is disabled, skip it. we still want to have a
            // zero-sized file with it's name though to signal that it's
            // disabled.
            if keyset.disabled {
                continue;
            }
            for key in &keyset.keys {
                match *key {
                    AuthorizedKeyEntry::Valid { ref key } => writeln!(keyfile, "{}", key)
                        .chain_err(|| format!("failed to write to file '{:?}'", keyfilename))?,
                    AuthorizedKeyEntry::Invalid { ref key } => writeln!(keyfile, "{}", key)
                        .chain_err(|| format!("failed to write to file '{:?}'", keyfilename))?,
                }
            }

            keyfile
                .sync_all()
                .chain_err(|| format!("failed to sync file '{:?}'", keyfilename))?;
        }

        replace_dir(
            &stage_dir,
            &self.authorized_keys_dir(),
            &self.stage_old_dir(),
        )
    }

    /// sync writes all the keys we have to authorized_keys. it writes the
    /// current state to a staging file and then moves that staging file to the
    /// authorized_keys path
    pub fn sync(&self) -> Result<()> {
        // if we have no keys, don't overwrite the authorized_keys file.
        // if the user wants to delete all their ssh keys, we won't help them
        if self.keys.is_empty() {
            return Err(ErrorKind::NoKeysFound(format!("{:?}", self.authorized_keys_dir())).into());
        }

        // switch users
        let _guard = switch_user(&self.user)?;

        // get our staging directory
        let stage_filename = self.stage_file();
        let mut stage_file = File::create(&stage_filename).chain_err(|| {
            format!(
                "failed to create or truncate staging file '{:?}'",
                stage_filename
            )
        })?;

        // note that this file is auto-generated
        writeln!(stage_file, "# auto-generated by update-ssh-keys")
            .chain_err(|| format!("failed to write to file '{:?}'", stage_filename))?;

        // write all the keys to the staging file
        for keyset in self.keys.values() {
            // if the keyset is disabled, skip it
            if keyset.disabled {
                continue;
            }
            for key in &keyset.keys {
                // only write the key to authorized_keys if it is valid
                if let AuthorizedKeyEntry::Valid { ref key } = *key {
                    writeln!(stage_file, "{}", key)
                        .chain_err(|| format!("failed to write to file '{:?}'", stage_filename))?;
                }
            }
        }

        stage_file
            .sync_all()
            .chain_err(|| format!("failed to sync file '{:?}'", stage_filename))?;
        drop(stage_file);

        // destroy the old authorized keys file and move the staging one to that
        // location
        fs::rename(&stage_filename, self.authorized_keys_file()).chain_err(|| {
            format!(
                "failed to move '{:?}' to '{:?}'",
                stage_filename,
                self.authorized_keys_file()
            )
        })?;

        let parent_path = stage_filename.parent().ok_or_else(|| {
            format!(
                "failed to sync parent directory of '{}'",
                stage_filename.display()
            )
        })?;
        let parent_dir_file = File::open(parent_path)
            .chain_err(|| format!("failed to open '{}' for syncing", parent_path.display()))?;
        parent_dir_file
            .sync_all()
            .chain_err(|| format!("failed to sync '{}'", parent_path.display()))?;

        Ok(())
    }

    /// read_all_keys reads all of the authorized keys files in a given
    /// directory. it returns an error if there is a nested directory, if any
    /// file operations fail, or if it can't parse any of the authorized_keys
    /// files
    fn read_all_keys(dir: &Path) -> Result<HashMap<String, AuthorizedKeySet>> {
        let dir_contents =
            fs::read_dir(dir).chain_err(|| format!("failed to read from directory {:?}", dir))?;
        let mut keys = HashMap::new();
        for entry in dir_contents {
            let entry =
                entry.chain_err(|| format!("failed to read entry in directory {:?}", dir))?;
            let path = entry.path();
            if path.is_dir() {
                // if it's a directory, we don't know what to do
                return Err(format!("'{:?}' is a directory", path).into());
            } else {
                let name = path
                    .file_name()
                    .ok_or_else(|| format!("failed to get filename for '{:?}'", path))?
                    .to_str()
                    .ok_or_else(|| format!("failed to convert filename '{:?}' to string", path))?;
                let from =
                    File::open(&path).chain_err(|| format!("failed to open file {:?}", path))?;
                let keyset = AuthorizedKeys::read_keys(from)?;
                keys.insert(
                    name.to_string(),
                    AuthorizedKeySet {
                        filename: name.to_string(),
                        disabled: keyset.is_empty(),
                        keys: keyset,
                    },
                );
            }
        }
        Ok(keys)
    }

    /// read_keys reads keys from a file in the authorized_keys file format,
    /// as described by the sshd man page. it logs a warning if it fails to
    /// parse any of the keys.
    pub fn read_keys<R>(r: R) -> Result<Vec<AuthorizedKeyEntry>>
    where
        R: Read,
    {
        let keybuf = BufReader::new(r);
        // authorized_keys files are newline-separated lists of public keys
        let mut keys = vec![];
        for key in keybuf.lines() {
            let key = key.chain_err(|| "failed to read public key")?;
            // skip any empty lines and any comment lines (prefixed with '#')
            if !key.is_empty() && !(key.trim().starts_with('#')) {
                match PublicKey::parse(&key) {
                    Ok(pkey) => keys.push(AuthorizedKeyEntry::Valid { key: pkey }),
                    Err(e) => {
                        println!("warning: failed to parse public key \"{}\": {}, omitting from authorized_keys", key, e);
                        keys.push(AuthorizedKeyEntry::Invalid { key })
                    }
                };
            }
        }
        Ok(keys)
    }

    /// open creates a new authorized_keys object. if there is an existing
    /// authorized_keys directory on disk it reads all the keys from that. if
    /// there is no directory already and we are told to create it, we add the
    /// existing authorized keys file as an entry, if it exists.
    ///
    /// before open actually does any of that, it switches it's uid for the span
    /// of the function and then switched back. it also opens a file lock on the
    /// directory that other instances of `update-ssh-keys` will respect. the
    /// file lock will automatically close when this structure goes out of
    /// scope. you can make sure it is unlocked by calling `drop` yourself in
    /// cases where you think the memory may leak (like if you are tossing boxes
    /// around etc).
    ///
    /// open blocks until it can grab the file lock.
    ///
    /// open returns an error if any file operations fail, if it failes to parse
    /// any of the public keys in the existing files, if it failes to change
    /// users, if it failes to grab the lock, or if create is false but the
    /// directory doesn't exist.
    pub fn open(user: User, create: bool, ssh_dir: Option<PathBuf>) -> Result<Self> {
        // switch users
        let _guard = switch_user(&user)?;
        // make a new file lock and lock it
        let lock = FileLock::try_new(&lock_file(&user))?;
        lock.lock()?;

        let ssh_dir = ssh_dir.unwrap_or_else(|| default_ssh_dir(&user));
        let akd = authorized_keys_dir(&ssh_dir);

        let keys = if akd.is_dir() {
            // read the existing keysets from the dir
            AuthorizedKeys::read_all_keys(&akd)?
        } else if !akd.exists() && create {
            // read the existing keyset from the file
            let filename = authorized_keys_file(&ssh_dir);
            if filename.exists() {
                let file = File::open(&filename).chain_err(|| {
                    format!("failed to open authorized keys file: '{:?}'", filename)
                })?;
                let mut keys = HashMap::new();
                keys.insert(
                    PRESERVED_KEYS_FILE.to_string(),
                    AuthorizedKeySet {
                        filename: PRESERVED_KEYS_FILE.to_string(),
                        disabled: false,
                        keys: AuthorizedKeys::read_keys(file)?,
                    },
                );
                keys
            } else {
                // if the authorized_keys file doesn't exist, we don't start
                // with any keys
                HashMap::new()
            }
        } else {
            // either the akd doesn't exist and create is false, or it exists
            // and is not a directory
            return Err(format!("'{:?}' doesn't exist or is not a directory", akd).into());
        };

        Ok(AuthorizedKeys {
            ssh_dir,
            user,
            keys,
            lock,
        })
    }

    /// get_keys gets the authorized keyset with the provided name
    pub fn get_keys(&self, name: &str) -> Option<&AuthorizedKeySet> {
        self.keys.get(name)
    }

    /// get_all_keys returns the hashmap from name to keyset containing all the
    /// keys we know about
    pub fn get_all_keys(&self) -> &HashMap<String, AuthorizedKeySet> {
        &self.keys
    }

    /// add_keys adds a list of public keys with the provide name. if replace is
    /// true, it will replace existing keys. if force is true, it will replace
    /// disabled keys.
    ///
    /// if the keys vector is empty, the function doesn't create an entry. empty
    /// entries are reserved for representing disabled keysets.
    ///
    /// add_keys returns an error if the key already exists and replace is
    /// false, or if the key is disabled and force is false
    pub fn add_keys(
        &mut self,
        name: &str,
        keys: Vec<AuthorizedKeyEntry>,
        replace: bool,
        force: bool,
    ) -> Result<Vec<AuthorizedKeyEntry>> {
        // if we are passed an empty vector of keys, don't create a file
        if keys.is_empty() {
            return Ok(vec![]);
        }

        if let Some(keyset) = self.keys.get(name) {
            if keyset.disabled && !force {
                return Err(ErrorKind::KeysDisabled(name.to_string()).into());
            } else if !replace {
                return Err(ErrorKind::KeysExist(name.to_string()).into());
            }
        }
        self.keys.insert(
            name.to_string(),
            AuthorizedKeySet {
                filename: name.to_string(),
                disabled: false,
                keys: keys.clone(),
            },
        );
        Ok(keys)
    }

    /// remove_keys removes the keyset with the given name.
    pub fn remove_keys(&mut self, name: &str) -> Vec<AuthorizedKeyEntry> {
        self.keys.remove(name).unwrap_or_default().keys
    }

    /// disable_keys disables keys with the given name. they can't be added
    /// again unless force is set to true when adding the set. disable_keys will
    /// succeed in disabling the key even if the key doesn't currently exist.
    pub fn disable_keys(&mut self, name: &str) -> Vec<AuthorizedKeyEntry> {
        if let Some(keyset) = self.keys.get_mut(name) {
            let keys = keyset.keys.clone();
            keyset.disabled = true;
            keyset.keys = vec![];
            return keys;
        }
        self.keys.insert(
            name.to_string(),
            AuthorizedKeySet {
                filename: name.to_string(),
                disabled: true,
                keys: vec![],
            },
        );
        vec![]
    }
}
