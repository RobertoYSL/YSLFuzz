# Lab Examples

This directory contains local lab pack manifests.

## Commands

```bash
uv run yslfuzz labs list
uv run yslfuzz labs show --lab simple-users
```

## simple-users

`simple-users` demonstrates the lab pack structure:

- `lab.json`: manifest.
- OpenAPI schema reference.
- ground-truth reference.
- benchmark config reference.

Lab packs are metadata and local fixtures. They do not start services or include credentials.
