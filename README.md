# update-ssh-keys

[![Github CI](https://github.com/flatcar/update-ssh-keys/actions/workflows/rust.yml/badge.svg)](https://github.com/flatcar/update-ssh-keys/actions)
![minimum rust 1.60](https://img.shields.io/badge/rust-1.60%2B-orange.svg)

`update-ssh-keys` is a command line tool and a library for managing openssh
authorized public keys. It keeps track of sets of keys with names, allows for
adding additional keys, as well as deleting and disabling them. For usage
information, see `update-ssh-keys -h` or run `cargo doc` to read the
documentation on the library api. 

The `update-ssh-keys` command line tool is included in Container Linux, so there
should be no reason to install it. If you would like to use this on a
non-Container Linux machine, you can build the project with `cargo build
--release`. The rust toolchain is required to build it. You can install `rustup`
to manage your rust toolchain - https://www.rustup.rs. 

`test/test_update_ssh_keys.rs` is a Rust program which tests the functionality
of the `update-ssh-keys` command line tool. If changes are made to
`update-ssh-keys`, that script should be run.
