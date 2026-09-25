# Remote TUI

Run the TUI on your machine against an Ember daemon in production, without SSH or access to Caddy's admin API. The session is read-only.

## Daemon

```bash
EMBER_METRICS_AUTH=ops:secret ember --daemon --expose :9191 --serve-remote \
  --expose-cert cert.pem --expose-key key.pem
```

`--serve-remote` adds `GET /snapshot` to the `--expose` server. It requires `--metrics-auth`, or `--expose-client-ca` for mTLS. Without `--expose-cert` the daemon warns that traffic is in clear text: only do this behind a TLS proxy. `/metrics` shares the same listener, TLS and credentials.

Remote sessions and refused requests are logged by the daemon.

## TUI

```bash
EMBER_REMOTE_AUTH=ops:secret ember --remote https://prod:9191 --ca-cert ca.pem
```

`--remote` requires `https://`, except for localhost. Run the same Ember version on the daemon and the TUI. On a multi-instance daemon, add `?instance=NAME` to the URL. The Logs, Caddy Config and Certificates tabs and worker restart are not available remotely.

## Security

The credentials give read access to everything the TUI shows, including the URIs FrankenPHP threads are serving, which may carry query strings.

## Try it

In `local/remote/`: `make certs && make up`, then `make start`.
