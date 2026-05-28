# Security

`nerve-agent` can execute shell commands on the machine where it runs. Treat the
agent token like a production secret and run the process with the least
privileges your workflow allows.

The agent sends its relay token in the WebSocket `Authorization: Bearer` header.
Avoid putting agent tokens in command history, logs, process managers with loose
permissions, or URLs. Older relays may still accept a `?token=` fallback, but
that path can leak through proxy and access logs and should be treated as
deprecated.

## Recommended Deployment

- Run the agent as a dedicated unprivileged user.
- Store the agent token in `/etc/nerve-agent.env` with restricted permissions.
- Store the agent ECDH key outside the repository, for example
  `/var/lib/nerve-agent/agent.key`.
- Avoid running as `root` unless your handler explicitly needs it.
- Use a small allowlisted handler script for production automation where
  possible.

## Known Limitation

The current agent trusts authenticated keyring updates received from the relay.
That keeps setup simple for the first public agent, but it is not the final
zero-knowledge trust model. A stronger release should verify keyring updates
with an out-of-band trust root or cryptographic proof.

## Reporting

Please report security issues privately through GitHub Security Advisories for
the `nerve-ink/nerve-agent` repository.
