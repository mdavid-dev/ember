//go:build integration_docker

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/alexandre-daubois/ember/internal/remote"
)

// TestIntegration_RemoteSmoke runs the local/remote stack: a FrankenPHP whose
// admin API is not published, and an Ember daemon serving the remote API over
// TLS. It covers the PR 1 steps of § 9.4 of the design: 1-3, 6, 7 and 9.
func TestIntegration_RemoteSmoke(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary not found in PATH; skipping remote smoke test")
	}
	_, repoRoot := composePaths(t)
	composeFile := filepath.Join(repoRoot, "local", "remote", "compose.yaml")

	ca := newTestCA(t)
	certPath, keyPath := ca.issue(t, "daemon", false)
	secrets := filepath.Dir(certPath)
	require.NoError(t, os.Rename(certPath, filepath.Join(secrets, "daemon.pem")))
	require.NoError(t, os.Rename(keyPath, filepath.Join(secrets, "daemon-key.pem")))
	sum := sha256.Sum256([]byte(remoteTestToken))
	auth := fmt.Sprintf("[[token]]\nname = \"alice\"\nsha256 = %q\nscopes = [\"snapshot\"]\n", hex.EncodeToString(sum[:]))
	require.NoError(t, os.WriteFile(filepath.Join(secrets, "auth.toml"), []byte(auth), 0o644))
	for _, f := range []string{"daemon.pem", "daemon-key.pem", "ca.pem"} {
		require.NoError(t, os.Chmod(filepath.Join(secrets, f), 0o644))
	}
	require.NoError(t, os.Chmod(secrets, 0o755))

	apiPort := portOf(t, freePortAddr(t))
	sitePort := portOf(t, freePortAddr(t))
	compose := func(ctx context.Context, args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, "docker", append([]string{"compose", "-p", "ember-remote-smoke", "-f", composeFile}, args...)...)
		c.Env = append(os.Environ(), "EMBER_REMOTE_SECRETS="+secrets, "REMOTE_API_PORT="+apiPort, "REMOTE_SITE_PORT="+sitePort)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c
	}
	run := func(timeout time.Duration, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return compose(ctx, args...).Run()
	}

	_ = run(time.Minute, "down", "--remove-orphans")
	require.NoError(t, run(10*time.Minute, "up", "-d", "--build"), "docker compose up failed")
	t.Cleanup(func() { _ = run(time.Minute, "down", "--remove-orphans") })

	// 1. The admin API is not reachable from the host.
	portCtx, portCancel := context.WithTimeout(context.Background(), 30*time.Second)
	out, err := compose(portCtx, "port", "frankenphp", "2019").Output()
	portCancel()
	assert.True(t, err != nil || strings.TrimSpace(string(out)) == "", "the admin port must not be published, got %q", out)

	// 2. A client with the right token gets a FrankenPHP snapshot.
	var sess *remote.Session
	require.Eventually(t, func() bool {
		sess, err = remote.Connect(context.Background(), remote.ClientOptions{
			URL:   "https://127.0.0.1:" + apiPort,
			Token: remoteTestToken,
			TLS:   &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
		})
		return err == nil
	}, 2*time.Minute, time.Second, "the daemon never accepted the handshake")
	defer sess.Close()
	var restarts atomic.Int32
	sess.OnEpochChange(func() { restarts.Add(1) })

	fetch := func(d time.Duration) (*model.State, error) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		snap, err := sess.Fetch(ctx)
		if err != nil {
			return nil, err
		}
		var st model.State
		st.Update(snap)
		return &st, nil
	}
	require.Eventually(t, func() bool {
		st, err := fetch(5 * time.Second)
		return err == nil && st.Current.HasFrankenPHP && len(st.Current.Threads.ThreadDebugStates) > 0
	}, time.Minute, 100*time.Millisecond, "no snapshot with FrankenPHP threads")

	// 3. Traffic gives a non-zero rate, computed client-side.
	trafficCtx, stopTraffic := context.WithCancel(context.Background())
	defer stopTraffic()
	go func() {
		for trafficCtx.Err() == nil {
			if resp, err := http.Get("http://127.0.0.1:" + sitePort + "/"); err == nil {
				_ = resp.Body.Close()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	var state model.State
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		snap, err := sess.Fetch(ctx)
		if err != nil {
			return false
		}
		state.Update(snap)
		return state.Derived.RPS > 0
	}, time.Minute, 10*time.Millisecond, "RPS stayed at zero under traffic")
	stopTraffic()
	t.Logf("step 3: RPS %.1f", state.Derived.RPS)

	// 6. A daemon restart is detected as a new epoch, and the stream resumes.
	require.NoError(t, run(2*time.Minute, "restart", "ember"))
	require.Eventually(t, func() bool {
		_, err := fetch(5 * time.Second)
		return err == nil && restarts.Load() == 1
	}, 2*time.Minute, 100*time.Millisecond, "no snapshot from the restarted daemon")

	// 7. Stopping FrankenPHP reaches the client as an unreachable status.
	require.NoError(t, run(time.Minute, "stop", "frankenphp"))
	stopped := time.Now()
	require.Eventually(t, func() bool {
		_, err := fetch(500 * time.Millisecond)
		return err != nil && strings.Contains(err.Error(), "the daemon cannot reach Caddy since")
	}, time.Minute, 50*time.Millisecond, "the outage never reached the client")
	t.Logf("step 7: outage reported %s after the stop (interval 1s)", time.Since(stopped).Round(100*time.Millisecond))

	// 9. The daemon's audit trail names the identity and never the token.
	logsCtx, logsCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer logsCancel()
	logs := compose(logsCtx, "logs", "--no-color", "ember")
	var buf bytes.Buffer
	logs.Stdout, logs.Stderr = &buf, &buf
	require.NoError(t, logs.Run())
	assert.Contains(t, buf.String(), `"msg":"remote.session.open"`)
	assert.Contains(t, buf.String(), `"msg":"remote.session.close"`)
	assert.Contains(t, buf.String(), `"identity":"alice"`)
	assert.NotContains(t, buf.String(), remoteTestToken)
	assert.NotContains(t, buf.String(), hex.EncodeToString(sum[:]))
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	i := strings.LastIndexByte(addr, ':')
	_, err := strconv.Atoi(addr[i+1:])
	require.NoError(t, err)
	return addr[i+1:]
}
