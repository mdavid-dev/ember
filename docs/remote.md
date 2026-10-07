# Remote TUI

Run the TUI on your machine against an Ember daemon in production, without SSH or access to Caddy's admin API. The session is read-only.

## Daemon

```bash
EMBER_METRICS_AUTH=ops:secret ember --daemon --expose :9191 --serve-remote \
  --expose-cert cert.pem --expose-key key.pem
```

`--serve-remote` adds `GET /logs` and `GET /certificates` to the `--expose` server, and relays under `/caddy/` the read requests of the TUI to Caddy's admin API. Under `/caddy/`, it refuses any other method or path; `/logs` and `/certificates` also answer `HEAD`, as Go's `ServeMux` does for a `GET` route. It requires `--metrics-auth`, or `--expose-client-ca` for mTLS, and a single `--addr`. Without `--expose-cert` the daemon warns that traffic is in clear text: only do this behind a TLS proxy. `/metrics` shares the same listener, TLS and credentials: under `--expose-client-ca`, Prometheus must present a client certificate too. So must anything that calls `/healthz`: a Kubernetes probe without a client certificate fails. `--expose-cert`, `--expose-key` and `--expose-client-ca` are read once at startup; SIGHUP only reloads the TLS material Ember uses towards Caddy, so restart the daemon to change them.

The daemon logs the opening of each TUI session (its first `/logs` request; a TUI that resumes after a daemon restart is not logged again), every request it refuses on the routes `--serve-remote` adds (`/caddy/…`, `/logs` and `/certificates`), and every read of Caddy's configuration, with the client certificate's common name under `--expose-client-ca`. It also logs when it starts and stops receiving Caddy's logs for the remote sessions.

## TUI

```bash
EMBER_REMOTE_AUTH=ops:secret ember --remote https://prod:9191 --ca-cert ca.pem
```

Against a daemon started with `--expose-client-ca`, present a certificate signed by that CA instead. If the daemon also sets `--metrics-auth`, pass both.

```bash
ember --remote https://prod:9191 --ca-cert ca.pem --client-cert me.pem --client-key me-key.pem
```

`--remote` requires `https://`, except for localhost, and refuses credentials in the URL: pass them with `EMBER_REMOTE_AUTH`. Run the same Ember version on the daemon and the TUI. The TUI reads Caddy as it does over SSH, at its own `--interval`, through the daemon. `--remote` exits before opening the TUI when the daemon cannot be reached, refuses the credentials, or was not started with `--serve-remote`; a host that does not answer can take up to 30 seconds to fail. With Caddy down behind a reachable daemon, the TUI starts and shows the outage as over SSH. Worker restart is not available remotely, and plugins are not loaded in a remote session. The Certificates tab shows what the daemon sees: the daemon dials the TLS hosts it monitors.

## Logs

The Logs tab works in a remote session, with the same effect on Caddy as a local TUI, limited to the session:

- As soon as a remote TUI connects, whatever tab it shows, the daemon registers the `__ember__` and `__ember_runtime__` sinks in Caddy and turns on access logs on every server that has no `logs` block. Caddy then also writes these access logs to its own output, as it does for a local TUI. See [Logs](logs.md).
- 30 seconds after the last remote TUI stopped asking, or when the daemon shuts down cleanly, it removes the sinks and the `logs` blocks it added. An empty `logging.logs` section it had to create stays, as it does after a local TUI. Several remote TUIs share one installation.
- Without a remote session, the daemon changes nothing in Caddy.

When the daemon refuses the logs with a 4xx answer, such as a 409 at startup or a 401 later in the session, an `ember.remote` error line in the runtime logs says why, and the Logs tab stops until the TUI restarts. When the daemon stops or cannot be reached, the TUI retries silently: the Logs tab stops updating, and resumes when the daemon is back. If Caddy cannot reach the daemon's listening address, the Logs tab stays empty without an error line, as for a local TUI.

The daemon listens for Caddy on a free loopback port when Caddy's admin API is on localhost. Otherwise start it with `--log-listen` and an address Caddy can reach: logs travel from Caddy to the daemon in clear text, as they do to a local TUI.

## Security

The credentials give read access to everything the TUI shows, including the URIs FrankenPHP threads are serving, which may carry query strings. They also give access to what Ember keeps of Caddy's log lines: client IP, host, method, full URI with its query string, status, and the messages of the runtime logs. A line Ember cannot parse is passed on as is.

The credentials also give access to Caddy's whole configuration, which may hold secrets: DNS provider tokens for ACME, `basic_auth` password hashes, headers added to requests sent to upstreams.

With the credentials, a single `/logs` request with any `after` of -1 or more, such as `/logs?after=0`, makes the daemon register the sinks and turn on access logs in Caddy, for 30 seconds.

## Try it

In `local/remote/`: `make certs && make up`, then `make start`, and `make traffic` in another terminal.

## See Also

- [CLI Reference](cli-reference.md)
- [Logs](logs.md)
- [Prometheus Export](prometheus-export.md)
