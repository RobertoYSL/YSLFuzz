# Labs

Lab packs describe local test targets, schemas, ground truth, and benchmark configs.

## CLI

```bash
uv run yslfuzz labs list
uv run yslfuzz labs show --lab simple-users
```

The default lab catalog root is `examples/labs`.

## Lab Manifest

A lab manifest includes:

- lab ID, name, version, and description;
- target type and setup type;
- schema references;
- optional ground-truth reference;
- optional benchmark config reference;
- tags and documentation notes.

The loader validates that referenced files stay inside the lab directory.

## Simple Users Lab

`examples/labs/simple-users/` contains a small local lab pack with:

- an OpenAPI schema reference;
- ground-truth metadata;
- benchmark config;
- manifest metadata.

Use it as a compact example for local dry-run scans, evaluation, and benchmark wiring.

## Safety Expectations

Labs are expected to be local or explicitly authorized. YSLFuzz does not bundle third-party
vulnerable apps unless they are present in the repository and documented.

## Future Lab Packs

New lab packs should include a manifest, local schema files, optional ground truth, optional
benchmark config, and clear setup notes. Do not include secrets.
