[![Crates.io](https://img.shields.io/crates/v/nom-mpq.svg)](https://crates.io/crates/nom-mpq)
[![Workflow Status](https://github.com/sebosp/nom-mpq/workflows/Rust/badge.svg)](https://github.com/sebosp/nom-mpq/actions?query=workflow%3A%22Rust%22)

# nom-mpq

Learning Nom Parsers and the MoPaQ format.

## Basic Example

### Commands
```
❯ cargo run --example basic -- --help
A nom parser for the MoPaQ archive format

Usage: basic [OPTIONS] --source <FILE> <COMMAND>

Commands:
  list            List Files
  extract-file    Extract a file from the archive
  extract-header  Extract a header from the archive
  help            Print this message or the help of the given subcommand(s)
```

### List files/sectors contained in the MPQ archive

```
❯ cargo run --example basic -- --source assets/SC2-Patch_4.12-2v2AI.SC2Replay list
replay.attributes.events     4247 bytes
replay.details      741 bytes
replay.details.backup      693 bytes
replay.game.events   126804 bytes
replay.gamemetadata.json      945 bytes
replay.initData     4714 bytes
replay.initData.backup     4640 bytes
replay.load.info       52 bytes
replay.message.events      148 bytes
replay.resumable.events       12 bytes
replay.server.battlelobby    33176 bytes
replay.smartcam.events    15086 bytes
replay.sync.events     1675 bytes
replay.sync.history        0 bytes
replay.tracker.events  1539841 bytes

```

### Extract a file/sector from the archive:
```
❯ cargo run --example basic -- --source assets/SC2-Patch_4.12-2v2AI.SC2Replay extract-file --name replay.gamemetadata.json
{
    "Title": "Heavy Artillery LE",
    "GameVersion": "5.0.9.87702",
    "DataBuild": "87702",
    "DataVersion": "F799E093428D419FD634CCE9B925218C",
    "BaseBuild": "Base87702",
    "Duration": 1342,
    "Players": [
        {
            "PlayerID": 1,
...
```

## Changelog

###  2.0.5

- tracing_off feature flag for enhanced performance.

## Sources
- [The_MoPaQ_Archive_Format](https://web.archive.org/web/20120222093346/http://wiki.devklog.net/index.php?title=The_MoPaQ_Archive_Format)
- [MPyQ](https://github.com/arkx/mpyq/)
