# open-share-protocol

**Purpose:** This repository contains machine- and human-readable protocol specs for Open Share: OpenAPI, JSON Schemas, device certificate & manifest formats, versioning rules, conformance & interop tests, and CI automation.

## Quick start (dev)

Requirements:
- node >= 16
- python >= 3.10
- pip
- jq

Validate OpenAPI:

```bash
npm install -g @stoplight/spectral
spectral lint openapi/openapi.yaml
````

Generate & run local conformance tests:

```bash
python3 -m pip install -r tests/conformance/requirements.txt
chmod +x tests/conformance/runner/run_local_tests.sh
tests/conformance/runner/run_local_tests.sh
```

## Layout

```
open-share-protocol/
├── README.md
├── openapi/
│   ├── openapi.yaml
│   └── components/schemas/*.schema.json
├── tests/
│   └── conformance/
└── .github/workflows/ci.yml
```
