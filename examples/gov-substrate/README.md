# AGT and Gov-Substrate execution bridge

Experimental, optional local integration. No core AGT package is changed.

This example requires both AGT's native enforcement engine and Gov-Substrate to
permit an action. The untrusted worker calls only the AGT controller's Unix
socket. The controller passes the native engine's effective arguments to
Gov-Substrate authorization and execution. Neither system overrides a denial
from the other. Operator approval is action-bound and uses a separate private
socket; pending or rejected approval cannot execute.

## Tested Sources

- AGT: `ae8c1aed70e71e3403ec2be9f3569c6b07fc18f4` (the native engine is built from this checkout).
- [Gov-Substrate](https://github.com/electricwolfemarshmallowhypertext/gov-substrate):
  v0.7.0, `03f715bde3f5f28c39870090036dc02e0e147f50`.
- Docker Desktop's Linux containers on Windows; Python 3.12.10.

Gov-Substrate is a separate AGPL-3.0 project. Its source is mounted read-only from
an existing checkout; it is not copied or relicensed into this repository. The
integration uses its actual authorization, execution, generation, circuit, audit,
and Docker supervisor implementations. No model inference or cloud API is used.

## Trust Boundary

The Docker host, controller, substrate service, and operator are trusted. The
worker is not. The worker is non-root, has no external network, has a read-only
root filesystem, and receives only the tool socket volume plus private temporary
storage. It receives no workspace, Docker socket, administrator socket, grant,
session token, or operator credential.

The substrate service alone receives Docker control and the circuit/operator
credentials. The controller holds a separate authenticated stop-handler
credential, not the circuit credential. AGT's real `KillSwitch` callback calls
that handler, which calls `Substrate.set_circuit()`. The controller requires the
receipt to match the bound DID, session, generation and immutable worker
container ID, with confirmed removal. An absent name or failed authentication
does not qualify as successful shutdown.

SMTP and HTTP receivers run in separate containers with no credentials or Docker
socket. SMTP shares the substrate network namespace because the v0.7.0 adapter
requires loopback. No service exposes a host port. The operator test harness runs
on the trusted host; its `docker exec` commands are not worker capabilities.

## Build

Prerequisites: Docker Desktop with Linux containers, Git, Python 3.12, pytest,
and an unchanged local Gov-Substrate v0.7.0 checkout at `E:\gov-substrate`.
Run from the AGT repository root in PowerShell:

```powershell
docker build -f examples/gov-substrate/Dockerfile.controller -t agt-gov-controller:local .
docker build -f examples/gov-substrate/Dockerfile.substrate -t agt-gov-substrate:local examples/gov-substrate
docker build -f examples/gov-substrate/Dockerfile.worker -t agt-gov-worker:local examples/gov-substrate
```

The controller build compiles the real Rust/native AGT SDK. The other images
contain the local adapter and isolated worker. Dependencies are confined to
these images, not added to AGT core.

## Real Deployment Regression

```powershell
cd examples/gov-substrate
$env:GOV_SUBSTRATE_SOURCE = 'E:\gov-substrate'
python -B -m pytest -c pytest.ini test_integration.py -v -s --basetemp .local/pytest
```

Expected: 25 `PASS` checks and `1 passed`. The run waits for a real 120-second
authorization expiry before starting its worker; it does not alter the clock or
the supervisor's separate 120-second lifetime. It creates fresh, test-only local
credentials in ignored `.local/` files. No credentials are embedded in source or
retained in `evidence/proof.json`.

The checks cover:

- Actual SMTP, file, and HTTP effects when both systems permit.
- Either system denying, and pending/rejected action-bound approval, with no effect.
- Changed arguments, reused grants/call IDs, real expiry, and revoked grants.
- Worker network/file/socket/credential bypass attempts and identity override.
- SIGTERM-resistant worker forced termination, immutable-ID removal, and late completion denial.
- Bad shutdown credentials and missing worker-identity confirmation, without false success.
- Independent recomputation of the actual Gov-Substrate audit event chain.

The failure-confirmation case deliberately renames a test-owned container. It
proves that an "absent" original name cannot certify removal of that same
immutable container ID. Cleanup still removes the tracked container by ID.

## Native Contract Regressions

From the AGT root:

```powershell
$example = (Resolve-Path examples/gov-substrate).Path
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges -v "${example}/test_bridge.py:/integration/test_bridge.py:ro" -v "${example}/bridge.py:/integration/bridge.py:ro" agt-gov-controller:local python -B -m unittest -v test_bridge
```

Expected: six tests pass. These use the real native AGT engine with recording
clients for focused contracts. They are separate from the real deployment proof.

## Evidence and Cleanup

[evidence/proof.json](evidence/proof.json) records pinned source/image identities,
AGT and Gov event correlation, actual results, receiver observations, Docker
shutdown events, and the scope of the successful run. A success is recorded only
after every assertion passes. Denials and unconfirmed results remain explicit.

The harness removes only its uniquely named Compose projects, volumes, and
tracked worker IDs in `finally` blocks. It does not prune Docker or affect other
containers. Ignored `.local/` files remain for local diagnostics and may be
removed after inspection. If the host process is forcibly interrupted, inspect
the generated `.local/<project>/compose.json` and stop only that exact project:

```powershell
docker compose -p <project> -f .local/<project>/compose.json down --volumes --remove-orphans
```

Then remove only any worker IDs recorded for that project. Do not run global
Docker cleanup commands.

These results establish the named local configuration, not resistance to a
compromised Docker host/kernel or verification of arbitrary external outcomes.
The SMTP observation proves receipt at the local test server, not final mailbox
delivery. The HTTP observation proves arrival at the local receiver, not a
remote business outcome. No hosted model or additional runtime has been tested.
