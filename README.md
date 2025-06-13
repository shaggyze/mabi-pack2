# Mabinogi Pack Utilities 2

New pack utilities for Mabinogi.

Works on *.it* packages.

Can run both in Windows and \*nix/MacOS.

## Build

Use rust 1.59 or above.

```bash
cargo build --release
```

## Usage

```
USAGE:
    mabi-pack2 [SUBCOMMAND]

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information
    -v               Shows only INFO and ERROR messages.
    -vv              Shows DEBUG, INFO, and ERROR messages.
    -vvv             Shows everything (TRACE, DEBUG, INFO, ERROR).

SUBCOMMANDS:
    extract    Extract a .it pack (SaltKey Optional, uses salts.txt)
    help       Print this message or the help of the given subcommand(s)
    list       Output the file list of a .it pack (SaltKey Optional, uses salts.txt)
    pack       Create a .it pack (SaltKey Required)
```

To extract all `.xml` and `.txt` files from a pack:

```
mabi-pack2 extract -i D:\Mabinogi\package\data_00788.it -o D:\data -k "SaltKey" --filter "\.xml" --filter "\.txt"
```

To list all files of a pack:

```
mabi-pack2 list -i D:\Mabinogi\package\data_00000.it -k "SaltKey"
```

To pack files to a .it file:

```
mabi-pack2 pack -i D:\Mabinogi\pkg -o zz_00.it -k "SaltKey"
```

*Note:* Renaming of \*.it files is not allowed, or extracting and listing will fail.

## License

This program is distributed under the MIT License.
