# DepSol

## What it does

Scans ELF files in `proprietary-files.txt` and recursively adds missing dependencies from an extracted firmware dump.

## Usage

Requires Python 3.10+ and `llvm-readelf` or GNU `readelf`.

Preview additions:

```sh
python3 resolve-blobs.py proprietary-files.txt /path/to/firmware_dump --dry-run
```

Write additions:

```sh
python3 resolve-blobs.py proprietary-files.txt /path/to/firmware_dump
```

## Credits

[LineageOS](https://github.com/LineageOS) for the [proprietary blob format documentation](https://github.com/LineageOS/lineage_wiki/blob/main/pages/internal/working_with_blobs.md) and [extraction fixup examples](https://github.com/LineageOS/android_device_oneplus_cheeseburger/blob/lineage-22.2/extract-files.py).
