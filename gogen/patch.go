package gogen

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"
	"unicode/utf8"

	"github.com/openconfig/goyang/pkg/yang"
)

// reCache is the global regexp cache used for speeding up the validation of
// pattern-restricted strings.
var reCache = newRegexpCache()

// newRegexpCache returns a regexpCache with all fields in a useable, empty
// state.
func newRegexpCache() *regexpCache {
	return &regexpCache{
		posix: map[string]*regexp.Regexp{},
		re2:   map[string]*regexp.Regexp{},
	}
}

// regexpCache stores previously-compiled Regexp objects.
// This helps the performance of validation of, say, a large prefix
// list that have the same pattern specification.
//
// # Concurrency Requirements
//
// Only the regexp cache map has to be protected by mutexes, since
// a Regexp is safe for concurrent use by multiple goroutines:
// https://golang.org/src/regexp/regexp.go
type regexpCache struct {
	posixMu sync.RWMutex
	posix   map[string]*regexp.Regexp

	re2Mu sync.RWMutex
	re2   map[string]*regexp.Regexp
}

// ValidateStringRestrictions checks that the given string matches the string
// schema's length and pattern restrictions (if any). It returns an error if
// the validation fails.
func ValidateStringRestrictions(schemaType *yang.YangType, stringVal string) error {
	// Check that the length is within the allowed range.
	allowedRanges := schemaType.Length
	strLen := uint64(utf8.RuneCountInString(stringVal))
	if !lengthOk(allowedRanges, strLen) {
		return fmt.Errorf("length %d is outside range %v", strLen, allowedRanges)
	}

	// Check that the value satisfies any regex patterns.
	patterns, isPOSIX := SanitizedPattern(schemaType)
	for _, p := range patterns {
		r, err := reCache.compilePattern(p, isPOSIX)
		if err != nil {
			return err
		}
		if !r.MatchString(stringVal) {
			return fmt.Errorf("%q does not match regular expression pattern %q", stringVal, r)
		}
	}
	return nil
}

// compilePattern returns the compiled regex for the given regex
// pattern. It caches previous look-ups for faster performance.
// Go's regexp implementation might be relatively slow compared to other
// languages: https://github.com/golang/go/issues/11646
func (c *regexpCache) compilePattern(pattern string, isPOSIX bool) (*regexp.Regexp, error) {
	regexCache := c.re2
	regexMutex := &c.re2Mu
	regexCompile := regexp.Compile
	if isPOSIX {
		regexCache = c.posix
		regexMutex = &c.posixMu
		regexCompile = regexp.CompilePOSIX
	}

	// Attempt to read a previously cached regexp.Regexp.
	if re := func() *regexp.Regexp {
		regexMutex.RLock()
		defer regexMutex.RUnlock()
		return regexCache[pattern]
	}(); re != nil {
		return re, nil
	}

	// Read unsuccessful (cache-miss). Compile and populate the cache.
	re, err := regexCompile(pattern)
	if err != nil {
		return nil, err
	}
	// Multiple unsuccessful readers might try to populate their own
	// compiled regexp.Regexp objects into the same cache entry.
	// This is ok, as since any regexp.Regexp value for the same cache
	// entry is equivalent, it does not matter which compiled instance is
	// introduced into the map, or returned to the caller.
	regexMutex.Lock()
	defer regexMutex.Unlock()
	regexCache[pattern] = re
	return re, nil
}

// lengthOk reports whether the given value of length falls within the ranges
// allowed by yrs. Always returns true is yrs is empty.
func lengthOk(yrs yang.YangRange, val uint64) bool {
	return isInRanges(yrs, yang.FromUint(val))
}

// isInRanges reports whether the given value falls within the ranges allowed by
// yrs. Always returns true is yrs is empty.
func isInRanges(yrs yang.YangRange, val yang.Number) bool {
	if len(yrs) == 0 {
		return true
	}
	for _, yr := range yrs {
		if isInRange(yr, val) {
			return true
		}
	}
	return false
}

// isInRange reports whether the given value falls within the range allowed by
// yr.
func isInRange(yr yang.YRange, val yang.Number) bool {
	return (val.Less(yr.Max) || val.Equal(yr.Max)) &&
		(yr.Min.Less(val) || yr.Min.Equal(val))
}

// SanitizedPattern returns the values of the posix-pattern extension
// statements for the YangType. If it's empty, then it returns the values from
// the pattern statements with anchors attached (if missing).
// It also returns whether the patterns are POSIX.
func SanitizedPattern(t *yang.YangType) ([]string, bool) {
	if len(t.POSIXPattern) != 0 {
		return t.POSIXPattern, true
	}
	var pat []string
	for _, p := range t.Pattern {
		// fixYangRegexp adds ^(...)$ around the pattern - the result is
		// equivalent to a full match of whole string.
		pat = append(pat, fixYangRegexp(p))
	}
	return pat, false
}

// fixYangRegexp takes a pattern regular expression from a YANG module and
// returns it into a format which can be used by the Go regular expression
// library. YANG uses a W3C standard that is defined to be implicitly anchored
// at the head or tail of the expression. See
// https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#regexs for details.
func fixYangRegexp(pattern string) string {
	var buf bytes.Buffer
	//var inEscape bool
	//var prevChar rune
	//addParens := false

	for i, ch := range pattern {
		if i == 0 /*&& ch != '^'*/ {
			buf.WriteRune('^')
			// Add parens around entire expression to prevent logical
			// subexpressions associating with leading/trailing ^ / $.
			buf.WriteRune('(')
			//addParens = true
		}

		//TODO ^ and $ means original
		switch ch {
		case '$':
			// Dollar signs need to be escaped unless they are at
			// the end of the pattern, or are already escaped.
			//if !inEscape && i != len(pattern)-1 {
			buf.WriteRune('\\')
			//}
		case '^':
			// Carets need to be escaped unless they are already
			// escaped, indicating set negation ([^.*]) or at the
			// start of the string.
			//if !inEscape && prevChar != '[' && i != 0 {
			buf.WriteRune('\\')
			//}
		}

		// If the previous character was an escape character, then we
		// leave the escape, otherwise check whether this is an escape
		// char and if so, then enter escape.
		//inEscape = !inEscape && ch == '\\'

		//if i == len(pattern)-1 && addParens && ch == '$' {
		//	buf.WriteRune(')')
		//}

		buf.WriteRune(ch)

		if i == len(pattern)-1 /*&& ch != '$'*/ {
			//if addParens {
			buf.WriteRune(')')
			//}
			buf.WriteRune('$')
		}

		//prevChar = ch
	}

	return buf.String()
}
