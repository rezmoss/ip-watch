// Package docker: dep-free Docker API client over the socket (raw HTTP).
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultSocket = "/var/run/docker.sock"

// Client: talks to daemon over unix socket.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient: socket (dflt if empty).
func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Container: subset of list entry.
type Container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
	Ports []struct {
		PrivatePort int `json:"PrivatePort"`
	} `json:"Ports"`
}

// Name: primary name, no leading slash.
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

func (c *Client) apiRequest(ctx context.Context, method, apiPath string, query url.Values, body io.Reader, contentType string) (*http.Response, error) {
	endpoint := "http://docker" + apiPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(req)
}

// Ping: daemon reachable?
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.apiRequest(ctx, http.MethodGet, "/_ping", nil, nil, "")
	if err != nil {
		return fmt.Errorf("docker socket %s: %w", c.socket, err)
	}
	resp.Body.Close()
	return nil
}

// List: running ctrs.
func (c *Client) List(ctx context.Context) ([]Container, error) {
	resp, err := c.apiRequest(ctx, http.MethodGet, "/containers/json", nil, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out []Container
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Exec: run cmd in ctr -> streams + exit code.
func (c *Client) Exec(ctx context.Context, container string, cmd []string) (stdout, stderr string, exitCode int, err error) {
	// root: cfg edit + reload needs privilege
	create := map[string]any{"AttachStdout": true, "AttachStderr": true, "Tty": false, "User": "0", "Cmd": cmd}
	body, _ := json.Marshal(create)
	resp, err := c.apiRequest(ctx, http.MethodPost, "/containers/"+container+"/exec", nil, bytes.NewReader(body), "application/json")
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", "", 0, apiError(resp)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", "", 0, err
	}

	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	startResp, err := c.apiRequest(ctx, http.MethodPost, "/exec/"+created.ID+"/start", nil, bytes.NewReader(startBody), "application/json")
	if err != nil {
		return "", "", 0, err
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		return "", "", 0, apiError(startResp)
	}
	outBuf, errBuf, err := demux(startResp.Body)
	if err != nil {
		return "", "", 0, err
	}

	inspectResp, err := c.apiRequest(ctx, http.MethodGet, "/exec/"+created.ID+"/json", nil, nil, "")
	if err != nil {
		return outBuf, errBuf, 0, err
	}
	defer inspectResp.Body.Close()
	var inspect struct {
		ExitCode int `json:"ExitCode"`
	}
	if err := json.NewDecoder(inspectResp.Body).Decode(&inspect); err != nil {
		return outBuf, errBuf, 0, err
	}
	return outBuf, errBuf, inspect.ExitCode, nil
}

// CopyFrom: file contents from ctr.
func (c *Client) CopyFrom(ctx context.Context, container, filePath string) ([]byte, error) {
	query := url.Values{"path": {filePath}}
	resp, err := c.apiRequest(ctx, http.MethodGet, "/containers/"+container+"/archive", query, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	tr := tar.NewReader(resp.Body)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("no file in archive of %s", filePath)
		}
		if err != nil {
			return nil, fmt.Errorf("read archive of %s: %w", filePath, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
}

// CopyTo: write data to dir/name in ctr.
func (c *Client) CopyTo(ctx context.Context, container, dir, name string, mode int64, data []byte) error {
	archive, err := tarFile(name, mode, data)
	if err != nil {
		return fmt.Errorf("build archive for %s/%s: %w", dir, name, err)
	}
	return c.putArchive(ctx, container, dir, archive)
}

// Exists: p exists in ctr?
func (c *Client) Exists(ctx context.Context, container, p string) bool {
	query := url.Values{"path": {p}}
	resp, err := c.apiRequest(ctx, http.MethodHead, "/containers/"+container+"/archive", query, nil, "")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *Client) putArchive(ctx context.Context, container, dir string, archive []byte) error {
	query := url.Values{"path": {dir}}
	resp, err := c.apiRequest(ctx, http.MethodPut, "/containers/"+container+"/archive", query, bytes.NewReader(archive), "application/x-tar")
	if err != nil {
		return fmt.Errorf("upload archive to %s:%s: %w", container, dir, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	return nil
}

// split muxed stream -> stdout/stderr (8-byte hdr + payload)
func demux(r io.Reader) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return out.String(), errb.String(), err
		}
		size := binary.BigEndian.Uint32(header[4:])
		dst := &out
		if header[0] == 2 {
			dst = &errb
		}
		if _, err := io.CopyN(dst, r, int64(size)); err != nil {
			return out.String(), errb.String(), err
		}
	}
	return out.String(), errb.String(), nil
}

func tarFile(name string, mode int64, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if mode == 0 {
		mode = 0o644
	}
	hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func apiError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Message != "" {
		msg = parsed.Message
	}
	return fmt.Errorf("docker api %s: %s", resp.Status, msg)
}
