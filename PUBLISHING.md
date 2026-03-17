# Publishing Guide

This document describes the requirements for publishing packages from the
Agent Governance Toolkit to public registries.

## Python Packages (PyPI)

### Published Packages

| Package | PyPI Name | Directory |
|---------|-----------|-----------|
| Agent OS Kernel | `agent-os-kernel` | `packages/agent-os` |
| AgentMesh Platform | `agentmesh-platform` | `packages/agent-mesh` |
| Agent Hypervisor | `agent-hypervisor` | `packages/agent-hypervisor` |
| Agent Runtime | `agent-runtime` | `packages/agent-runtime` |
| Agent SRE | `agent-sre` | `packages/agent-sre` |
| Agent Governance Toolkit | `agent-governance-toolkit` | `packages/agent-compliance` |
| Agent Lightning | `agent-lightning` | `packages/agent-lightning` |

### Publishing Method

All Python packages are published to PyPI via **ESRP Release** using an Azure
DevOps pipeline (`pipelines/pypi-publish.yml`).

> **⚠️ GitHub Actions Trusted Publishers are not used for PyPI publishing.**
> The GitHub Actions workflow (`.github/workflows/publish.yml`) builds and
> attests packages but does **not** publish them. Actual publishing goes
> through the ADO pipeline.

### Building Packages

```bash
# Install build tools
python -m pip install --upgrade pip build

# Build a specific package
cd packages/agent-os
python -m build
```

Each package produces:
- A wheel (`.whl`) — **required**
- A source distribution (`.tar.gz`) — recommended

### Package Metadata Requirements

All packages must include:
- **Author**: `Microsoft Corporation`
- **Contact email**: A team distribution list (not a personal email)
- **License**: MIT (with `License :: OSI Approved :: MIT License` classifier)
- **README**: `readme = "README.md"` in `pyproject.toml`

### Naming Conventions

- Do **not** start package names with `microsoft` or `windows` (reserved)
- If using `azure` branding, coordinate with the Azure SDK team
- All packages are published under the **microsoft** PyPI account

### Linux Wheels

For packages with native extensions targeting Linux, use `manylinux` tags
(e.g., `manylinux2014_x86_64`), **not** `linux_x86_64`.

## .NET Packages (NuGet)

The .NET SDK (`packages/agent-governance-dotnet`) is published to NuGet with
ESRP Authenticode and NuGet signing.

## Contact

- Python packaging questions: python@microsoft.com
- ESRP Release support: esrprelpm@microsoft.com
