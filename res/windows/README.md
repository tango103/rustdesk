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


## Important scope note

This repository/workflow builds the **RustDesk client/host** application (`rustdesk.exe`).
It does **not** build the standalone RustDesk Server binaries (`hbbs`/`hbbr` from the
`rustdesk-server` project).

So, `id_whitelist.txt` here applies to host-mode checks in `rustdesk.exe`, not to the
original `rustdesk-server` binaries.
