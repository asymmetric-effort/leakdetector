package decoder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Decoded holds a decoded value and its encoding type.
type Decoded struct {
	Value    string
	Encoding string
	Depth    int
}

// Decode recursively decodes a string through supported encodings.
// maxDepth controls recursion depth (0 = no decoding).
func Decode(s string, maxDepth int) []Decoded {
	if maxDepth <= 0 {
		return nil
	}

	var results []Decoded
	seen := make(map[string]struct{})
	decodeRecursive(s, 1, maxDepth, &results, seen)
	return results
}

func decodeRecursive(s string, depth, maxDepth int, results *[]Decoded, seen map[string]struct{}) {
	if depth > maxDepth {
		return
	}
	if _, ok := seen[s]; ok {
		return
	}
	seen[s] = struct{}{}

	// Try base64
	if len(s) >= 16 {
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err == nil && isPrintable(decoded) {
			d := Decoded{
				Value:    string(decoded),
				Encoding: "base64",
				Depth:    depth,
			}
			*results = append(*results, d)
			decodeRecursive(d.Value, depth+1, maxDepth, results, seen)
		}
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err == nil && isPrintable(decoded) {
			val := string(decoded)
			if _, exists := seen[val]; !exists {
				d := Decoded{
					Value:    val,
					Encoding: "base64url",
					Depth:    depth,
				}
				*results = append(*results, d)
				decodeRecursive(d.Value, depth+1, maxDepth, results, seen)
			}
		}
	}

	// Try hex
	if len(s) >= 32 && isHex(s) {
		decoded, err := hex.DecodeString(s)
		if err == nil && isPrintable(decoded) {
			d := Decoded{
				Value:    string(decoded),
				Encoding: "hex",
				Depth:    depth,
			}
			*results = append(*results, d)
			decodeRecursive(d.Value, depth+1, maxDepth, results, seen)
		}
	}

	// Try percent-encoding
	if strings.Contains(s, "%") {
		decoded, err := url.QueryUnescape(s)
		if err == nil && decoded != s {
			d := Decoded{
				Value:    decoded,
				Encoding: "percent",
				Depth:    depth,
			}
			*results = append(*results, d)
			decodeRecursive(d.Value, depth+1, maxDepth, results, seen)
		}
	}
}

func isPrintable(b []byte) bool {
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Tags returns tags describing the decoding chain.
func Tags(decoded []Decoded) []string {
	tags := make([]string, 0, len(decoded))
	for _, d := range decoded {
		tags = append(tags, fmt.Sprintf("decoded:%s", d.Encoding))
		if d.Depth > 1 {
			tags = append(tags, fmt.Sprintf("decode-depth:%d", d.Depth))
		}
	}
	return tags
}
