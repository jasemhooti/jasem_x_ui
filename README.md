# jasem_x_ui

A fork of [3x-ui](https://github.com/MHSanaei/3x-ui) (v3.8.5) that turns any share link or subscription (Clash YAML, sing-box JSON, Xray JSON) into an outbound, runs Xray-core v26.6.27 by default with a sing-box v1.14.2 sidecar for the rest, and installs and updates offline on servers with no GitHub access. Backups stay compatible with upstream 3x-ui (`x-ui.db`).

Licensed under GPL-3.0, like upstream.

## Install / نصب

English and فارسی (same command; the panel UI defaults to Persian):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/jasemhooti/jasem_x_ui/main/install.sh)
```

After install the menu is `jasem-x-ui`, the service is `jasem_x_ui`, files live in `/usr/local/jasem_x_ui/` (data `/etc/jasem_x_ui/`, logs `/var/log/jasem_x_ui/`). Only Linux amd64 and arm64 are built.

بعد از نصب، منوی مدیریت با دستور `jasem-x-ui` باز می‌شود و سرویس `jasem_x_ui` نام دارد.

## Offline install and update / نصب و بروزرسانی آفلاین

Download `jasem_x_ui-linux-amd64.tar.gz` (or `-arm64`) and `install.sh` from the Releases page on any machine, copy them to the server and run:

```bash
# install
bash install.sh --local /root/jasem_x_ui-linux-amd64.tar.gz
# update
jasem-x-ui update --local /root/jasem_x_ui-linux-amd64.tar.gz
```

برای نصب آفلاین، فایل `jasem_x_ui-linux-amd64.tar.gz` (یا `arm64`) را از بخش Releases دانلود و به سرور منتقل کنید و دستورهای بالا را اجرا کنید. Xray، sing-box، فایل‌های geo و acme.sh داخل همین آرشیو هستند.

`--mirror <base-url>` downloads from your own mirror instead of GitHub. The URL is a directory serving `jasem_x_ui-linux-<arch>.tar.gz` (optionally with its `.sha256`, `install.sh` and `update.sh`):

```bash
bash install.sh --mirror https://mirror.example.com/jasem_x_ui
jasem-x-ui update --mirror https://mirror.example.com/jasem_x_ui
```

If `<archive>.sha256` sits next to the local archive it is verified before installing.

## Docker

```bash
docker compose up -d
```

Data is kept in `./db/` (mounted at `/etc/jasem_x_ui/`).

## Credits

Built on [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) and [XTLS/Xray-core](https://github.com/XTLS/Xray-core).
