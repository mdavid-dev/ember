# Remote TUI

Run the TUI on your machine against an Ember daemon in production, without SSH or access to Caddy's admin API. The session is read-only.

## Daemon

```bash
EMBER_METRICS_AUTH=ops:secret ember --daemon --expose :9191 --serve-remote \
  --expose-cert cert.pem --expose-key key.pem
```

`--serve-remote` adds `GET /snapshot`, `GET /certificates` and `GET /logs` to the `--expose` server. It requires `--metrics-auth`, or `--expose-client-ca` for mTLS. Without `--expose-cert` the daemon warns that traffic is in clear text: only do this behind a TLS proxy. `/metrics` shares the same listener, TLS and credentials.

Remote sessions, refused requests, and the installation and removal of the log sinks are logged by the daemon.

## TUI

```bash
EMBER_REMOTE_AUTH=ops:secret ember --remote https://prod:9191 --ca-cert ca.pem
```

`--remote` requires `https://`, except for localhost. Run the same Ember version on the daemon and the TUI. On a multi-instance daemon, add `?instance=NAME` to the URL. The Caddy Config tab and worker restart are not available remotely; the Certificates and Logs tabs show what the daemon sees.

## Logs

The Logs tab works in a remote session, with the same effect on Caddy as a local TUI, limited to the session:

- When a remote TUI starts reading the logs, the daemon registers the `__ember__` and `__ember_runtime__` sinks in Caddy and turns on access logs on every server that has no `logs` block. Caddy then also writes these access logs to its own output, as it does for a local TUI. See [Logs](logs.md).
- 30 seconds after the last remote TUI stopped asking, or when the daemon stops, it removes the sinks and the `logs` blocks it added. An empty `logging.logs` section it had to create stays, as it does after a local TUI. Several remote TUIs share one installation.
- Without a remote TUI, the daemon changes nothing in Caddy.

The daemon listens for Caddy on a free loopback port when Caddy's admin API is on localhost. Otherwise start it with `--log-listen` and an address Caddy can reach: logs travel from Caddy to the daemon in clear text, as they do to a local TUI. A multi-instance daemon does not serve logs, and the tab says why.

## Security

The credentials give read access to everything the TUI shows, including the URIs FrankenPHP threads are serving, which may carry query strings. They also give access to what Ember keeps of Caddy's log lines: client IP, host, method, full URI with its query string, status, and the messages of the runtime logs. A line that is not valid JSON is passed on as is.

## Try it

In `local/remote/`: `make certs && make up`, then `make start`.
