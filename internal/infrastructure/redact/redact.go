// Package redact strips secrets from URLs, command lines, and text.
package redact

import "regexp"

const Mask = "***"

var (
	urlCred = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^:/@\s]+(?::[^@/\s]*)?@`)
	kv      = regexp.MustCompile(`(?i)((?:--?)?[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|credential|private[_-]?key|pwd)[\w.-]*)(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|\S+)`)
	bearer  = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]{8,}`)
	known   = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})\b`)
)

func URL(s string) string { return urlCred.ReplaceAllString(s, "${1}"+Mask+"@") }

func Text(s string) string {
	if s == "" {
		return s
	}
	s = URL(s)
	s = bearer.ReplaceAllString(s, "${1}"+Mask)
	s = known.ReplaceAllString(s, Mask)
	s = kv.ReplaceAllString(s, "${1}${2}"+Mask)
	return s
}
