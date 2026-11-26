package filesystem

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBody = "test-content"

func newTempFileSystemWithClient(client *http.Client) *TempFileSystem {
	return &TempFileSystem{files: []*os.File{}, httpClient: client}
}

func TestDownloadTempFile_DirectHTTPS_Succeeds(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testBody))
	}))
	t.Cleanup(srv.Close)

	parsedURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	fs := newTempFileSystemWithClient(srv.Client())
	t.Cleanup(func() { _ = fs.RemoveTempFiles() })

	path, err := fs.DownloadTempFile("", "test-*", parsedURL)
	require.NoError(t, err)
	assert.NotEmpty(t, path)
}

func TestDownloadTempFile_SameHostPathRedirect_Succeeds(t *testing.T) {
	// A single TLS server that redirects /redirect -> /content on the same host.
	// Go resolves this to an absolute URL with the same scheme+host before calling
	// checkRedirect, so the same-host redirect is exercised end-to-end.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/content", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testBody))
	}))
	t.Cleanup(srv.Close)

	// Use the default test client (no SSRF check) — the same-host redirect goes to
	// 127.0.0.1 which would otherwise be blocked. This test verifies the download
	// path works with redirects; policy enforcement is covered by checkRedirect tests.
	parsedURL, err := url.Parse(srv.URL + "/redirect")
	require.NoError(t, err)

	fs := newTempFileSystemWithClient(srv.Client())
	t.Cleanup(func() { _ = fs.RemoveTempFiles() })

	path, err := fs.DownloadTempFile("", "test-*", parsedURL)
	require.NoError(t, err)
	assert.NotEmpty(t, path)
}

// --- checkRedirect policy unit tests ---

func makeReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u.String(), nil)
	require.NoError(t, err)
	return req
}

func TestCheckRedirect_HTTPSPublicHost_Allowed(t *testing.T) {
	req := makeReq(t, "https://raw.githubusercontent.com/some/repo/file.yaml")
	err := checkRedirect(req, nil)
	require.NoError(t, err)
}

func TestCheckRedirect_HTTPScheme_Blocked(t *testing.T) {
	req := makeReq(t, "http://example.com/file.yaml")
	err := checkRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect blocked")
}

func TestCheckRedirect_Loopback_Blocked(t *testing.T) {
	req := makeReq(t, "https://127.0.0.1/secret")
	err := checkRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect blocked")
}

func TestCheckRedirect_RFC1918_Blocked(t *testing.T) {
	for _, addr := range []string{
		"https://10.0.0.1/secret",
		"https://172.16.0.1/secret",
		"https://192.168.1.1/secret",
	} {
		req := makeReq(t, addr)
		err := checkRedirect(req, nil)
		require.Error(t, err, "expected block for %s", addr)
		assert.Contains(t, err.Error(), "redirect blocked")
	}
}

func TestCheckRedirect_LinkLocal_Blocked(t *testing.T) {
	req := makeReq(t, "https://169.254.169.254/latest/meta-data/")
	err := checkRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect blocked")
}
