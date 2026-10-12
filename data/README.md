# RSSMB Data Directory

This directory holds share data served by RSSMB.

## Setup

```sh
mkdir -p public homes
chown -R 1000:1000 .   # RSSMB runs as UID 1000
chmod 755 .
```

## Shares

- `public/` — Guest-accessible public share
- `homes/`  — User home directories (requires authentication)

## Docker Compose

The `docker/compose.yml` mounts these directories into the container at `/data`.
