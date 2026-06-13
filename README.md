# Nerve Agent

[![Website](https://img.shields.io/badge/website-nerve.ink-111214)](https://nerve.ink)
[![Go Reference](https://pkg.go.dev/badge/github.com/nerve-ink/nerve-agent.svg)](https://pkg.go.dev/github.com/nerve-ink/nerve-agent)

[Website](https://nerve.ink) · [Docs](https://nerve.ink/docs.html) · [Send signals with nerve-cli](https://github.com/nerve-ink/nerve-cli)

`nerve-agent` is the server-side action runner for Nerve. It connects to the
Nerve relay, receives E2E-encrypted command envelopes, verifies Ed25519
signatures, executes trusted commands, and returns encrypted output.

The relay should only see encrypted payloads. The agent is the component you run
on infrastructure you control.

If you only need deploy alerts, cron notifications, or one-way status messages,
start with [`nerve-cli`](https://github.com/nerve-ink/nerve-cli). The agent is
for signed actions on a machine you already trust.

## Install

Install Go first if it is not already on the machine:

https://go.dev/doc/install

Then install the agent:

```bash
go install github.com/nerve-ink/nerve-agent@latest
```

Make sure your Go bin directory is on `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Connect

Create a pipe in the Nerve mobile app, open Pipe Setup, choose **Run agent**,
then copy the token. The agent authenticates its WebSocket connection with an
`Authorization: Bearer` header, so the token is not placed in the URL.

```bash
nerve-agent -server api.nerve.ink:443 -token YOUR_AGENT_TOKEN
```

Now send a one-shot command from the pipe:

```bash
cat /etc/os-release
```

The agent verifies the command signature, executes it on the host, and sends the
output back to the same pipe.

For local backend development:

```bash
nerve-agent -server localhost:8080 -token YOUR_AGENT_TOKEN
```

## Flags

```text
-server    Relay host:port. Defaults to localhost:8080.
-token     Agent token from Nerve Pipe Setup. Required.
-handler   Optional allowlisted script command. Receives decrypted envelope JSON on stdin.
-key-file  ECDH private key path. Defaults to ~/.nerve/agent.key.
-timeout   Max execution time per command. Defaults to 60s.
```

## Command Behavior

The agent is a bounded action runner, not SSH or an interactive PTY.

- Each command is a one-shot signed action.
- Commands time out after `-timeout` (default: `60s`).
- On timeout, the agent kills the whole command process group and sends the
  captured output plus a timeout error back to the pipe.
- Interactive programs such as `vim`, `top`, or shell sessions are not a V1
  product surface.
- Long-running checks should be wrapped in scripts that print a bounded summary
  and exit.

For commands that may run forever, use shell-level limits too:

```bash
timeout 20s ping 8.8.8.8
```

## Handler / Runbook Mode

For production automation, prefer a small allowlisted handler over arbitrary
shell commands. The handler receives the decrypted envelope JSON on stdin and
can decide which local runbook to execute.

Example wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail

payload="$(cat)"
cmd="$(printf '%s' "$payload" | jq -r '.payload_raw | fromjson? | .cmd // empty')"

case "$cmd" in
  restart-nginx)
    exec sudo /bin/systemctl restart nginx
    ;;
  deploy-status)
    exec /usr/local/bin/check-deploy-status
    ;;
  *)
    echo "denied: unknown runbook" >&2
    exit 126
    ;;
esac
```

Then run:

```bash
nerve-agent -server api.nerve.ink:443 -token YOUR_AGENT_TOKEN -handler /usr/local/bin/nerve-runbook
```

## systemd

An example unit is available at `examples/systemd/nerve-agent.service`.

Example environment file:

```bash
sudo useradd --system --home /var/lib/nerve-agent --shell /usr/sbin/nologin nerve-agent
sudo install -d -m 0750 /var/lib/nerve-agent
sudo install -m 0644 examples/systemd/nerve-agent.service /etc/systemd/system/nerve-agent.service
sudo tee /etc/nerve-agent.env >/dev/null <<EOF
NERVE_SERVER=api.nerve.ink:443
NERVE_AGENT_TOKEN=YOUR_AGENT_TOKEN
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now nerve-agent
```

If you install with `go install`, copy the binary into `/usr/local/bin` for the
systemd unit:

```bash
sudo install -m 0755 "$(go env GOPATH)/bin/nerve-agent" /usr/local/bin/nerve-agent
```

## Security Model

- The agent can execute commands on the host where you run it.
- Treat the agent token as a privileged credential.
- Prefer a locked-down system user and an allowlisted `-handler` for production.
- Commands must decrypt before execution.
- Commands must include a valid Ed25519 signature.
- Signatures are verified against trusted keys sent by the authenticated relay.
- Commands outside the replay window are rejected.
- Command output is encrypted before it is sent back when channel keys are ready.

If an agent token leaks, rotate the **Run agent** credential from Pipe Setup and
restart the agent with the new token.

This project is early. Review `SECURITY.md` before running the agent on
production infrastructure.
