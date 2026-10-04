package link

import (
	"fmt"
	"regexp"
	"strings"
)

// Skipped describes one subscription entry that could not be imported.
type Skipped struct {
	Line   string `json:"line"`
	Reason string `json:"reason"`
}

// Subscription is the result of parsing a subscription body.
type Subscription struct {
	Outbounds  []Outbound
	Identities []string
	Skipped    []Skipped

	seen map[string]int
}

var clashProxiesRe = regexp.MustCompile(`(?m)^proxies\s*:`)

// ParseSubscription accepts the raw body returned by a subscription URL: a
// (base64) list of share links, a Clash YAML, a sing-box JSON or Xray JSON.
func ParseSubscription(body []byte) *Subscription {
	sub := &Subscription{}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return sub
	}
	if !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") && !clashProxiesRe.MatchString(text) {
		if decoded, ok := tryBase64(text); ok {
			text = strings.TrimSpace(decoded)
		}
	}
	switch {
	case strings.HasPrefix(text, "{") || strings.HasPrefix(text, "["):
		sub.addJSON(text)
	case clashProxiesRe.MatchString(text):
		sub.addClash(text)
	default:
		sub.addLines(text)
	}
	return sub
}

// ParseSubscriptionBody returns the parsed outbounds and their identities,
// dropping the skipped entries; see ParseSubscription for those.
func ParseSubscriptionBody(body []byte) ([]Outbound, []string, error) {
	sub := ParseSubscription(body)
	return sub.Outbounds, sub.Identities, nil
}

func (s *Subscription) addLines(text string) {
	for _, ln := range splitLines(text) {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		res, err := ParseLink(ln)
		if err != nil || res == nil {
			s.skip(ln, err)
			continue
		}
		s.add(res)
	}
}

// add keeps a repeated identity distinct: it would otherwise share one stored
// tag, shifting both tags on every refresh.
func (s *Subscription) add(res *ParseResult) {
	identity := res.Identity
	if s.seen == nil {
		s.seen = map[string]int{}
	}
	if n := s.seen[res.Identity]; n > 0 {
		identity = fmt.Sprintf("%s#%d", res.Identity, n)
	}
	s.seen[res.Identity]++
	s.Outbounds = append(s.Outbounds, res.Outbound)
	s.Identities = append(s.Identities, identity)
}

func (s *Subscription) skip(line string, err error) {
	reason := "unsupported or malformed entry"
	if err != nil {
		reason = err.Error()
	}
	if r := []rune(reason); len(r) > 120 {
		reason = string(r[:120])
	}
	if r := []rune(line); len(r) > 80 {
		line = string(r[:80])
	}
	s.Skipped = append(s.Skipped, Skipped{Line: line, Reason: reason})
}
