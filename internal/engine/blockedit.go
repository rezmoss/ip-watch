package engine

import "strings"

// markers keyed by managed path: re-apply/removal exact
func beginMark(key string) string { return "# >>> ip-watch:" + key + " >>>" }
func endMark(key string) string   { return "# <<< ip-watch:" + key + " <<<" }

// strip prior block (begin..end incl)
func stripManaged(src, key string) string {
	begin, end := beginMark(key), endMark(key)
	var out []string
	skipping := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == begin:
			skipping = true
		case trimmed == end:
			skipping = false
		case !skipping:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// insert payload after first matched header (selector: err only)
func injectAfterHeader(conf []byte, key string, payload []string, indent, selector string, matchHeader func(raw, trimmed string) bool) ([]byte, error) {
	src := stripManaged(string(conf), key)
	lines := strings.Split(src, "\n")

	target := -1
	for i, line := range lines {
		if matchHeader(line, strings.TrimSpace(line)) {
			target = i
			break
		}
	}
	if target == -1 {
		if selector != "" {
			return nil, errNoBlock("no matching block for selector " + selector)
		}
		return nil, errNoBlock("no block found to edit")
	}

	block := []string{indent + beginMark(key)}
	for _, p := range payload {
		block = append(block, indent+p)
	}
	block = append(block, indent+endMark(key))

	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:target+1]...)
	out = append(out, block...)
	out = append(out, lines[target+1:]...)
	return []byte(strings.Join(out, "\n")), nil
}

type errNoBlock string

func (e errNoBlock) Error() string { return string(e) }
