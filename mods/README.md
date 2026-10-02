# mods/

Place `.mod` instruction files here. mabi-patcher will list them in the Dashboard → Mod Loader panel and expose them via the REST API (`GET /api/v1/mods`).

## Format

`.mod` files use TOML syntax. See `example.mod` for a full annotated template, or run:

```
mabi-patcher mod template
```

to print a blank template to stdout.

## CLI usage

```
# Inspect a .mod file
mabi-patcher mod inspect -f mods/example.mod

# List all .mod files in this directory
mabi-patcher mod list -d mods/
```

## REST API

When mabi-patcher is running (GUI or `mabi-patcher serve`), the API is available at `http://127.0.0.1:7331`:

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/status` | App version and status |
| POST | `/api/v1/extract` | Extract an archive |
| POST | `/api/v1/pack` | Pack a folder |
| POST | `/api/v1/list` | List archive entries |
| POST | `/api/v1/mod/apply` | Parse and apply a `.mod` |
| GET | `/api/v1/mods` | List `.mod` files |
| GET | `/api/v1/mod-template` | Get blank template |
