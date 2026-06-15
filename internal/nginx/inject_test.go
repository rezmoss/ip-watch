package nginx

import "strings"

import "testing"

const sampleConf = `
http {
    server {
        listen 80;
        server_name example.com www.example.com;
        location / {
            proxy_pass http://app;
        }
    }
    server {
        listen 8080;
        server_name admin.example.com;
    }
}
`

func TestInjectFirstBlock(t *testing.T) {
	out, err := InjectInclude([]byte(sampleConf), "/etc/nginx/ip-watch/web1.conf",
		"include /etc/nginx/ip-watch/web1.conf;", "")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "# >>> ip-watch:/etc/nginx/ip-watch/web1.conf >>>") {
		t.Fatal("begin marker missing")
	}
	// include before 1st server's location
	if strings.Index(s, "include /etc/nginx/ip-watch/web1.conf;") > strings.Index(s, "location / {") {
		t.Fatal("include not inside first server block")
	}
}

// upstream `server host:port;` lines must not fool the block parser
func TestInjectWithUpstreamBlock(t *testing.T) {
	conf := `
http {
    upstream app {
        server app1:8080;
        server app2:8080;
    }
    server {
        listen 80;
        server_name example.com;
        location / {
            proxy_pass http://app;
        }
    }
}
`
	out, err := InjectInclude([]byte(conf), "k", "include k;", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// include must land inside the server block, after the upstream directives
	inc := strings.Index(s, "include k;")
	if inc < strings.Index(s, "server app2:8080;") {
		t.Fatal("include placed before the server block (parser stopped at upstream)")
	}
	if inc > strings.Index(s, "location / {") {
		t.Fatal("include not inside the server block")
	}
}

func TestInjectBySelector(t *testing.T) {
	out, err := InjectInclude([]byte(sampleConf), "k", "include k;", "admin.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// include in admin block: after 1st block, before admin server_name line.
	inc := strings.Index(s, "include k;")
	if inc < strings.Index(s, "www.example.com") || inc > strings.Index(s, "admin.example.com") {
		t.Fatal("include not placed in selected block")
	}
}

func TestInjectIdempotent(t *testing.T) {
	once, err := InjectInclude([]byte(sampleConf), "k", "include k;", "")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := InjectInclude(once, "k", "include k;", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(twice), "include k;") != 1 {
		t.Fatalf("expected exactly one include after re-apply, got:\n%s", twice)
	}
}

func TestUnknownSelectorErrors(t *testing.T) {
	if _, err := InjectInclude([]byte(sampleConf), "k", "include k;", "nope.com"); err == nil {
		t.Fatal("expected error for unknown server_name")
	}
}
