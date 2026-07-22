# mabi-patcher .mod instruction file — example
# https://github.com/shaggyze/mabi-pack2

[meta]
name        = "Example Performance Mod"
version     = "1.0.0"
author      = "ShaggyZE"
description = "Removes dungeon fog and autoproduction caps"
game        = "NA"
tags        = ["performance", "gameplay"]

[pack]
output      = "uotiara_00001.it"
pack_key    = "})wWb4?-sVGHNoPKpc"
extract_key = "@6QeTuOaDgJlZcBm#9"
wrap_data   = true

# File replacements (archive_path = path inside the .it archive)
[[files]]
archive_path = "data/db/dungeondb.xml"
source       = "mod_files/dungeondb.xml"
action       = "replace"

[[files]]
archive_path = "data/db/production.xml"
source       = "mod_files/production.xml"
action       = "replace"

# Feature flag toggles applied during pack
[features]
enable  = []
disable = []

# Import named entries from uotiaralist.ini
[from_ini]
path    = "uotiaralist.ini"
entries = [
  "Autoproduction Uncaps",
  "Dungeon Fog Removal 1",
  "Dungeon Fog Removal 2",
  "Clock-Weather Minimize",
]

# API settings — set public = true to expose via REST API at /api/v1/mods
[api]
public       = false
allow_remote = false
