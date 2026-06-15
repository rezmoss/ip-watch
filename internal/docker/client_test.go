package docker

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// frame: one muxed-stream frame.
func frame(stream byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, []byte(payload)...)
}

func TestDemux(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(frame(1, "out-a"))
	stream.Write(frame(2, "err-1"))
	stream.Write(frame(1, "out-b"))

	stdout, stderr, err := demux(&stream)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "out-aout-b" {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "err-1" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestTarFileRoundTrip(t *testing.T) {
	archive, err := tarFile("web1.conf", 0o644, []byte("allow 1.2.3.0/24;\n"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "web1.conf" || hdr.Typeflag != tar.TypeReg {
		t.Fatalf("unexpected header %+v", hdr)
	}
	body, _ := io.ReadAll(tr)
	if string(body) != "allow 1.2.3.0/24;\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestGuessEngine(t *testing.T) {
	cases := map[string]string{
		"nginx:alpine":        "nginx",
		"caddy:2":             "caddy",
		"httpd:2.4":           "apache",
		"haproxytech/haproxy": "haproxy",
		"redis:7":             "",
	}
	for image, want := range cases {
		if got := guessEngine(Container{Image: image}); got != want {
			t.Errorf("guessEngine(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestContainerName(t *testing.T) {
	c := Container{Names: []string{"/web", "/web/alias"}}
	if c.Name() != "web" {
		t.Fatalf("Name() = %q", c.Name())
	}
}
