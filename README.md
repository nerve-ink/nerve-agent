# Nerve Agent

`nerve-agent` is the server-side daemon for Nerve. It connects to the Nerve
relay, receives E2E-encrypted command envelopes, verifies Ed25519 signatures,
executes trusted commands, and returns encrypted output.

The relay should only see encrypted payloads. The agent is the component you run
on infrastructure you control.

## Install

```bash
go install github.com/nerve-ink/nerve-agent@latest
```

Make sure your Go bin directory is on `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Connect

Create a channel in the Nerve iOS app, open **Agent Setup**, then copy the token.
The agent authenticates its WebSocket connection with an `Authorization: Bearer`
header, so the token is not placed in the URL.

```bash
nerve-agent -server api.nerve.ink:443 -token YOUR_AGENT_TOKEN
```

For local backend development:

```bash
nerve-agent -server localhost:8080 -token YOUR_AGENT_TOKEN
```

## Flags

```text
-server    Relay host:port. Defaults to localhost:8080.
-token     Agent token from Nerve Agent Setup. Required.
-handler   Optional script command. Receives decrypted envelope JSON on stdin.
-key-file  ECDH private key path. Defaults to ~/.nerve/agent.key.
-timeout   Max execution time per command. Defaults to 60s.
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

- Commands must decrypt before execution.
- Commands must include a valid Ed25519 signature.
- Signatures are verified against trusted keys sent by the authenticated relay.
- Commands outside the replay window are rejected.
- Command output is encrypted before it is sent back when channel keys are ready.

This project is early. Review `SECURITY.md` before running the agent on
production infrastructure.
