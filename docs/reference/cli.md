# Command-Line Help for `libra`

This document contains the help content for the `libra` command-line program.

**Command Overview:**

* [`libra`↴](#libra)
* [`libra key`↴](#libra-key)
* [`libra key create`↴](#libra-key-create)
* [`libra key revoke`↴](#libra-key-revoke)
* [`libra key list`↴](#libra-key-list)
* [`libra principal`↴](#libra-principal)
* [`libra principal create`↴](#libra-principal-create)
* [`libra principal remove`↴](#libra-principal-remove)
* [`libra principal list`↴](#libra-principal-list)
* [`libra config`↴](#libra-config)
* [`libra config init`↴](#libra-config-init)

## `libra`

An NGSI-LD authentication and authorization proxy

**Usage:** `libra [COMMAND]`

###### **Subcommands:**

* `key`: Issue, revoke and list API keys
* `principal`: Create, remove and list the principals keys belong to
* `config`: Work with the configuration file



## `libra key`

Issue, revoke and list API keys

**Usage:** `libra key <COMMAND>`

###### **Subcommands:**

* `create`: Issue a key for a principal. The key is printed once and never stored
* `revoke`: Revoke a key from the next request on
* `list`: List every key, without its secret



## `libra key create`

Issue a key for a principal. The key is printed once and never stored

**Usage:** `libra key create --principal <PRINCIPAL> <--expires-at <EXPIRES_AT>|--expires-in <EXPIRES_IN>>`

###### **Options:**

* `--principal <PRINCIPAL>`: The principal the key authenticates as
* `--expires-at <EXPIRES_AT>`: An RFC 3339 time, such as 2027-01-31T00:00:00Z
* `--expires-in <EXPIRES_IN>`: A duration from now, such as 90d or P30D. Days count as 24 hours



## `libra key revoke`

Revoke a key from the next request on

**Usage:** `libra key revoke <ID>`

###### **Arguments:**

* `<ID>`: The key's id, as `libra key list` shows it



## `libra key list`

List every key, without its secret

**Usage:** `libra key list`



## `libra principal`

Create, remove and list the principals keys belong to

**Usage:** `libra principal <COMMAND>`

###### **Subcommands:**

* `create`: Create a principal
* `remove`: Remove a principal and every key it holds
* `list`: List every principal



## `libra principal create`

Create a principal

**Usage:** `libra principal create [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>`: Its name, which a policy's `principals` condition matches

###### **Options:**

* `--group <GROUPS>`: A group it belongs to. Repeat for several
* `--role <ROLES>`: A role it holds. Repeat for several



## `libra principal remove`

Remove a principal and every key it holds

**Usage:** `libra principal remove <NAME>`

###### **Arguments:**

* `<NAME>`: Its name



## `libra principal list`

List every principal

**Usage:** `libra principal list`



## `libra config`

Work with the configuration file

**Usage:** `libra config <COMMAND>`

###### **Subcommands:**

* `init`: Print a configuration file with every key at its built-in default



## `libra config init`

Print a configuration file with every key at its built-in default.

The file is optional; Libra runs on the same defaults without one. Redirect the output to start one, `libra config init > libra.toml`, then keep only the keys you change.

**Usage:** `libra config init`



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
