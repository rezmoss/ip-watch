package nginx

import (
	"fmt"
	"strings"
)

// markers wrap managed blocks by key; re-apply replaces, removal exact.
func beginMarker(key string) string { return "# >>> ip-watch:" + key + " >>>" }
func endMarker(key string) string   { return "# <<< ip-watch:" + key + " <<<" }

// InjectInclude: wrap includeLine in a server block (idempotent)
func InjectInclude(conf []byte, key, includeLine, serverName string) ([]byte, error) {
	src := stripManaged(string(conf), key)

	blocks := findServerBlocks(src)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no server block found in config")
	}
	target := blocks[0]
	if serverName != "" {
		match, ok := blockForServerName(blocks, serverName)
		if !ok {
			return nil, fmt.Errorf("no server block matches server_name %q", serverName)
		}
		target = match
	}

	indent := target.indent + "    "
	managed := beginMarker(key) + "\n" +
		indent + includeLine + "\n" +
		indent + endMarker(key)

	// insert after opening brace line
	insertAt := lineEndAfter(src, target.openBrace)
	var b strings.Builder
	b.WriteString(src[:insertAt])
	b.WriteString(indent)
	b.WriteString(managed)
	b.WriteString("\n")
	b.WriteString(src[insertAt:])
	return []byte(b.String()), nil
}

func blockForServerName(blocks []serverBlock, name string) (serverBlock, bool) {
	for _, b := range blocks {
		for _, n := range b.serverNames {
			if n == name {
				return b, true
			}
		}
	}
	return serverBlock{}, false
}

// stripManaged: drop begin..end lines inclusive.
func stripManaged(src, key string) string {
	begin, end := beginMarker(key), endMarker(key)
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case t == begin:
			skipping = true
		case t == end:
			skipping = false
		case !skipping:
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

// lineEndAfter: index past newline after pos.
func lineEndAfter(s string, pos int) int {
	for i := pos; i < len(s); i++ {
		if s[i] == '\n' {
			return i + 1
		}
	}
	return len(s)
}

type serverBlock struct {
	openBrace   int // '{' index
	closeBrace  int // matching '}' index
	serverNames []string
	indent      string // block open-line indent
}

// findServerBlocks: top-level server{} blocks, skip comments & quotes.
func findServerBlocks(s string) []serverBlock {
	var blocks []serverBlock
	i := 0
	for i < len(s) {
		idx := indexServerKeyword(s, i)
		if idx < 0 {
			break
		}
		open := indexBraceAfter(s, idx+len("server"))
		if open < 0 {
			// a `server` directive (e.g. in upstream), not a block — skip
			i = idx + len("server")
			continue
		}
		close := matchBrace(s, open)
		if close < 0 {
			break
		}
		body := s[open+1 : close]
		blocks = append(blocks, serverBlock{
			openBrace:   open,
			closeBrace:  close,
			serverNames: parseServerNames(body),
			indent:      lineIndent(s, idx),
		})
		i = close + 1
	}
	return blocks
}

// indexServerKeyword: next standalone `server` at/after from, not in comment.
func indexServerKeyword(s string, from int) int {
	for i := from; i+6 <= len(s); i++ {
		if s[i] == '#' {
			i = endOfLine(s, i)
			continue
		}
		if s[i:i+6] != "server" {
			continue
		}
		if i > 0 && isWord(s[i-1]) {
			continue
		}
		after := i + 6
		if after < len(s) && isWord(s[after]) {
			continue // server_name, etc.
		}
		return i
	}
	return -1
}

// indexBraceAfter: next '{' after pos, -1 if ';' first (directive).
func indexBraceAfter(s string, pos int) int {
	for i := pos; i < len(s); i++ {
		switch s[i] {
		case '#':
			i = endOfLine(s, i)
		case ';':
			return -1
		case '{':
			return i
		}
	}
	return -1
}

// matchBrace: index of '}' matching '{' at open.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '#':
			i = endOfLine(s, i)
		case '"', '\'':
			i = skipQuoted(s, i)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func parseServerNames(body string) []string {
	var names []string
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if h := strings.IndexByte(line, '#'); h >= 0 {
			line = line[:h]
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "server_name") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSpace(line[len("server_name"):]), ";")
		names = append(names, strings.Fields(line)...)
	}
	return names
}

func endOfLine(s string, i int) int {
	for ; i < len(s); i++ {
		if s[i] == '\n' {
			return i
		}
	}
	return len(s) - 1
}

func skipQuoted(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == q {
			return j
		}
	}
	return len(s) - 1
}

func lineIndent(s string, pos int) string {
	start := pos
	for start > 0 && s[start-1] != '\n' {
		start--
	}
	end := start
	for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
		end++
	}
	return s[start:end]
}

func isWord(b byte) bool {
	return b == '_' || b == '-' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
