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

//! update-ssh-keys
//!
//! this command allows users of container linux to administer ssh keys

extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate openssh_keys;
extern crate users;

extern crate update_ssh_keys;

use clap::{crate_version, Arg, Command};
use std::fs::File;
use std::path::PathBuf;
use update_ssh_keys::errors::*;
use update_ssh_keys::*;
use users::get_current_username;

#[derive(Clone, Debug)]
struct Config {
    user: String,
    ssh_dir: Option<PathBuf>,
    command: UssCommand,
}

#[derive(Clone, Debug)]
enum UssCommand {
    Add {
        name: String,
        force: bool,
        replace: bool,
        stdin: bool,
        keyfiles: Vec<String>,
    },
    Delete {
        name: String,
    },
    Disable {
        name: String,
    },
    List,
    Sync,
}

quick_main!(run);

fn run() -> Result<()> {
    let config = config().chain_err(|| "command line configuration")?;

    let user = users::get_user_by_name(&config.user)
        .ok_or_else(|| format!("failed to find user with name '{}'", config.user))?;

    let mut aks = AuthorizedKeys::open(user, true, config.ssh_dir.clone()).chain_err(|| {
        format!(
            "failed to open authorized keys directory for user '{}'",
            config.user
        )
    })?;

    match config.command {
        UssCommand::Add {
            name,
            force,
            replace,
            stdin,
            keyfiles,
        } => {
            let keys = if stdin {
                // read the keys from stdin
                AuthorizedKeys::read_keys(std::io::stdin())?
            } else {
                // keys are in provided files
                let mut keys = vec![];
                for keyfile in keyfiles {
                    let file = File::open(&keyfile)
                        .chain_err(|| format!("failed to open keyfile '{:?}'", keyfile))?;
                    keys.append(&mut AuthorizedKeys::read_keys(file)?);
                }
                keys
            };
            let res = aks.add_keys(&name, keys, replace, force);
            match res {
                Ok(keys) => {
                    println!("Adding/updating {}:", name);
                    for key in &keys {
                        if let AuthorizedKeyEntry::Valid { ref key } = *key {
                            println!("{}", key.to_fingerprint_string());
                        }
                    }
                }
                Err(Error(ErrorKind::KeysDisabled(name), _)) => {
                    println!("Skipping add {} for {}, disabled.", name, config.user)
                }
                Err(Error(ErrorKind::KeysExist(_), _)) => {
                    println!("Skipping add {} for {}, already exists.", name, config.user)
                }
                _ => {
                    res.chain_err(|| "failed to add keys")?;
                }
            }
        }
        UssCommand::Delete { name } => {
            println!("Removing {}:", name);
            for key in aks.remove_keys(&name) {
                if let AuthorizedKeyEntry::Valid { ref key } = key {
                    println!("{}", key.to_fingerprint_string());
                }
            }
        }
        UssCommand::Disable { name } => {
            println!("Disabling {}:", name);
            for key in aks.disable_keys(&name) {
                if let AuthorizedKeyEntry::Valid { ref key } = key {
                    println!("{}", key.to_fingerprint_string());
                }
            }
        }
        UssCommand::List => {
            let keys = aks.get_all_keys();
            println!("All keys for {}:", config.user);
            for (name, keyset) in keys {
                println!("{}:", name);
                for key in &keyset.keys {
                    if let AuthorizedKeyEntry::Valid { ref key } = *key {
                        println!("{}", key.to_fingerprint_string())
                    }
                }
            }
        }
        UssCommand::Sync => {}
    }

    aks.write()
        .chain_err(|| "failed to update authorized keys directory")?;
    aks.sync()
        .chain_err(|| "failed to update authorized keys")?;

    println!("Updated {:?}", aks.authorized_keys_file());

    Ok(())
}

pub const USS_TEMPLATE: &str = "\
{name}
{usage-heading} {usage}

{all-args}

{about-with-newline}";

pub const ABOUT_TEXT: &str = "\
This tool provides a consistent way for different systems to add ssh public
keys to a given user account, usually the default current user.
If -a, -A, -d, nor -D are provided then the authorized_keys file is simply
regenerated using the existing keys.

With the -a option keys may be provided as files on the command line. If no
files are provided with the -a option the keys will be read from stdin.";

fn config() -> Result<Config> {
    // get the default user by figuring out the current user; if the current user
    // is root (or doesn't exist) then use 'core'.
    let default_user = get_current_username().map_or("core".into(), |u| {
        let name = u.to_string_lossy();
        if name == "root" {
            "core".into()
        } else {
            name.into_owned()
        }
    });

    // setup cli
    let matches = Command::new("update-ssh-keys")
        .version(crate_version!())
        .help_template(USS_TEMPLATE)
        .about(ABOUT_TEXT)
        .arg(Arg::new("user").short('u').help(format!(
            "Update the given user's authorized_keys file. [{}]",
            default_user
        )))
        .arg(
            Arg::new("no-replace")
                .short('n')
                .help("When adding, don't replace an existing key with the given name."),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .help("List the names and number of keys currently installed."),
        )
        .arg(
            Arg::new("add")
                .short('a')
                .help("Add the given keys, using the given name to identify them."),
        )
        .arg(
            Arg::new("add-force")
                .short('A')
                .help("Add the given keys, even if it was disabled with '-D'."),
        )
        .arg(
            Arg::new("delete")
                .short('d')
                .help("Delete keys identified by the given name."),
        )
        .arg(
            Arg::new("disable")
                .short('D')
                .help("Disable the given set from being added with '-a'."),
        )
        .arg(
            Arg::new("ssh_dir")
                .short('s')
                .long("ssh-dir")
                .help("location of the ssh configuration directory (defaults to ~/.ssh)"),
        )
        .arg(Arg::new("keys").num_args(1..).help("path to key files"))
        .get_matches();

    let command = matches
        .get_one::<String>("add")
        .map(|name| UssCommand::Add {
            name: name.into(),
            force: false,
            replace: !matches.contains_id("no-replace"),
            stdin: !matches.contains_id("keys"),
            keyfiles: matches
                .get_many::<String>("keys")
                .map(|vals| vals.map(|s| s.into()).collect::<Vec<_>>())
                .unwrap_or_default(),
        })
        .or_else(|| {
            matches
                .get_one::<String>("add-force")
                .map(|name| UssCommand::Add {
                    name: name.into(),
                    force: true,
                    replace: !matches.contains_id("no-replace"),
                    stdin: !matches.contains_id("keys"),
                    keyfiles: matches
                        .get_many::<String>("keys")
                        .map(|vals| vals.map(|s| s.into()).collect::<Vec<_>>())
                        .unwrap_or_default(),
                })
        })
        .or_else(|| {
            matches
                .get_one::<String>("delete")
                .map(|name| UssCommand::Delete { name: name.into() })
        })
        .or_else(|| {
            matches
                .get_one::<String>("disable")
                .map(|name| UssCommand::Disable { name: name.into() })
        })
        .unwrap_or(if matches.contains_id("list") {
            UssCommand::List
        } else {
            UssCommand::Sync
        });

    let user = matches
        .get_one::<String>("user")
        .map_or(default_user, String::from);

    let ssh_dir = matches.get_one::<String>("ssh_dir").map(PathBuf::from);

    Ok(Config {
        user,
        ssh_dir,
        command,
    })
}
