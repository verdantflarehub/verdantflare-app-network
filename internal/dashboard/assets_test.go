package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	html := []byte("<!doctype html><p>application</p>")
	index, _ := json.Marshal(map[string]any{"schemaVersion": 1, "files": map[string]string{"index.html": hash(html)}})
	d := declaration{SchemaVersion: 1, AppID: "network", AppVersion: "0.1.0"}
	d.Dashboard.EntryRef = "dashboard/index.html"
	d.Dashboard.ArtifactDigest = "sha256:" + hash(index)
	d.Dashboard.Adapter = "wujie"
	d.Dashboard.SDKMajor = 1
	d.Dashboard.MinimumSDKVersion = "1.1.0"
	d.Dashboard.RequiredCapabilities = []string{"app.request", "navigation.request"}
	d.Dashboard.OptionalCapabilities = []string{}
	d.Dashboard.AppAPIPolicyRef = "network-management-v1"
	metadata, _ := json.Marshal(d)
	for name, data := range map[string][]byte{"index.html": html, "asset-index.json": index, "dashboard-declaration.json": metadata} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestAssetIntegrityAndConfinement(t *testing.T) {
	root := fixture(t)
	assets, err := Load(root, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, mime, ok := assets.File("index.html"); !ok || mime != "text/html; charset=utf-8" {
		t.Fatal("entry unavailable")
	}
	for _, name := range []string{"../index.html", "/index.html", "x/../../index.html", "%2e%2e/index.html", "unknown.js", "x\\index.html"} {
		if _, _, ok := assets.File(name); ok {
			t.Fatal("unindexed resource served")
		}
	}
	if _, err := Load(root, "0.1.1"); err == nil {
		t.Fatal("version substitution accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, "0.1.0"); err == nil {
		t.Fatal("tamper accepted")
	}
	// Existing server holds verified immutable bytes, never rereads altered files.
	if content, _, _ := assets.File("index.html"); string(content) == "changed" {
		t.Fatal("mutable byte source")
	}
}
