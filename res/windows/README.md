# Windows Sciter pre-build helper

Use this helper to prepare a `Release/` folder that already contains:

- `rustdesk.exe` built with `inline` UI (no runtime dependency on `src/ui` files)
- `sciter.dll` downloaded automatically

## Command

```bash
python res/windows/prepare_sciter_release.py
```

Optional target examples:

```bash
python res/windows/prepare_sciter_release.py --target x86_64-pc-windows-msvc
python res/windows/prepare_sciter_release.py --target i686-pc-windows-msvc
```
