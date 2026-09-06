// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package client talks to the GLPI plugin's agent endpoints.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client is the agent's side of the supervisor protocol. osqueryd speaks to
// GLPI on its own; this covers only what osquery has no concept of — enrolling
// the supervisor and asking what version it should be running.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a client, optionally pinning a private CA.
//
// A custom CA is the normal case rather than the exception: most GLPI
// installations behind this will use an internal certificate, and the
// alternative — disabling verification — would leave the enrollment secret and
// every query result open to anyone on the path.
func New(baseURL, caCertPath string) (*Client, error) {
	if !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		return nil, fmt.Errorf("server URL must be https (got %q)", baseURL)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 15 * time.Second,
	}

	if caCertPath != "" {
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}

		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA certificate %s contains no usable certificate", caCertPath)
		}

		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}, nil
}

func (c *Client) post(path string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "glpi-osquery-agent")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	if response == nil {
		return nil
	}

	return json.Unmarshal(payload, response)
}

// EnrollRequest identifies the machine to the server.
type EnrollRequest struct {
	EnrollSecret   string `json:"enroll_secret"`
	HostIdentifier string `json:"host_identifier"`
	HardwareUUID   string `json:"hardware_uuid"`
	Platform       string `json:"platform"`
	Arch           string `json:"arch"`
	AgentVersion   string `json:"agent_version"`
	// Where our status listener answers, so GLPI's device page knows the port
	// to reach us on.
	ListenPort int `json:"listen_port"`
}

type enrollResponse struct {
	AgentToken       string   `json:"agent_token"`
	TrustedAddresses []string `json:"trusted_addresses"`
	Error            string   `json:"error"`
}

// Enroll trades the shared secret for this agent's own token, and returns any
// addresses the server says may query the status listener.
func (c *Client) Enroll(req EnrollRequest) (string, []string, error) {
	var resp enrollResponse
	if err := c.post("/plugins/glpiosquery/front/agent-enroll.php", req, &resp); err != nil {
		return "", nil, err
	}
	if resp.AgentToken == "" {
		return "", nil, fmt.Errorf("server did not issue a token: %s", resp.Error)
	}

	return resp.AgentToken, resp.TrustedAddresses, nil
}

// Package is one downloadable artifact the server wants installed.
type Package struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// PackageSet is a map of kind ("agent", "osquery") to package.
//
// It decodes an empty JSON array as well as an object, because PHP renders an
// empty associative array as `[]` rather than `{}` — and "nothing to install"
// is the overwhelmingly common answer. A strict map would fail to parse almost
// every check-in, which then stops the agent ever confirming an update as
// healthy and eventually triggers a rollback of a perfectly good version.
//
// Being liberal here also matters because an agent can legitimately be talking
// to an older plugin: that is precisely the state self-update creates.
type PackageSet map[string]Package

func (p *PackageSet) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		*p = PackageSet{}
		return nil
	}

	var m map[string]Package
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*p = m

	return nil
}

// Extension is one published osquery extension the server wants installed.
type Extension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// InstalledExtension is what the agent reports back about its own disk.
type InstalledExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// UpdateResponse is the server's answer to "what should I be running?".
type UpdateResponse struct {
	UpdateAvailable bool       `json:"update_available"`
	Packages        PackageSet `json:"packages"`

	// The complete set of published extensions this agent should have, not a
	// list of changes. An empty list means "none", and removing an extension
	// from an endpoint is expressed by it no longer appearing here — so this
	// field being absent has to be distinguishable from it being empty, or a
	// response from an older plugin would uninstall everything. Hence the
	// pointer: nil is "this server does not manage extensions", and an empty
	// slice is "you should have none".
	Extensions     *[]Extension `json:"extensions"`
	CheckInterval  int          `json:"check_interval"`
	Ring           int          `json:"ring"`
	RolloutPercent int          `json:"rollout_percent"`

	// Who may query this agent's status listener. Refreshed on every check-in
	// so the list can be changed centrally in GLPI.
	TrustedAddresses []string `json:"trusted_addresses"`

	// The server does not recognise this agent any more — revoked, or a forced
	// re-enrolment. Carried in a 200 response because that is how osquery's
	// protocol signals it, so it must be read from the body rather than
	// inferred from a status code.
	NodeInvalid bool `json:"node_invalid"`
}

// UpdateRequest reports what is running now.
type UpdateRequest struct {
	AgentToken     string `json:"agent_token"`
	AgentVersion   string `json:"agent_version"`
	OsqueryVersion string `json:"osquery_version"`
	Arch           string `json:"arch"`

	// What is actually on disk, which the server cannot infer from what it last
	// offered. Always sent, empty included, so that "installed nothing" is
	// reported rather than looking like an agent too old to answer.
	Extensions []InstalledExtension `json:"extensions"`
}

// CheckUpdate asks the server what this agent should be running.
func (c *Client) CheckUpdate(req UpdateRequest) (*UpdateResponse, error) {
	var resp UpdateResponse
	if err := c.post("/plugins/glpiosquery/front/update.php", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Download fetches a package body to the supplied writer, returning the number
// of bytes written.
func (c *Client) Download(url string, w io.Writer, limit int64) (int64, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download %s returned %d", url, resp.StatusCode)
	}

	// Bounded so a wrong or hostile URL cannot fill the endpoint's disk.
	return io.Copy(w, io.LimitReader(resp.Body, limit))
}

// RequestInventory relays a "run inventory now" from GLPI's device page.
func (c *Client) RequestInventory(token string) error {
	return c.post("/plugins/glpiosquery/front/refresh.php",
		map[string]string{"agent_token": token}, nil)
}
