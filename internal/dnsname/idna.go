package dnsname

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var unicodeDots = strings.NewReplacer(
	"\u3002", ".",
	"\uff0e", ".",
	"\uff61", ".",
)

// ToASCII converts each non-ASCII DNS label to its IDNA lookup form.
// ASCII service labels such as _acme-challenge are preserved.
func ToASCII(name string) (string, error) {
	name = unicodeDots.Replace(strings.TrimSpace(name))
	if name == "" || name == "." {
		return name, nil
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if label == "" {
			return "", fmt.Errorf("DNS name contains an empty label")
		}
		ascii, err := labelToASCII(label)
		if err != nil {
			return "", fmt.Errorf("invalid DNS label %q: %w", label, err)
		}
		if len(ascii) > 63 {
			return "", fmt.Errorf("DNS label %q exceeds 63 octets", label)
		}
		labels[index] = strings.ToLower(ascii)
	}
	ascii := strings.Join(labels, ".")
	if len(ascii) > 253 {
		return "", fmt.Errorf("DNS name exceeds 253 octets")
	}
	return ascii + ".", nil
}

// ToUnicode returns a display form while keeping labels that cannot be decoded.
func ToUnicode(name string) string {
	name = unicodeDots.Replace(strings.TrimSpace(name))
	if name == "" || name == "." {
		return name
	}
	trailingDot := strings.HasSuffix(name, ".")
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if !strings.HasPrefix(strings.ToLower(label), "xn--") {
			continue
		}
		if decoded, err := idna.Lookup.ToUnicode(label); err == nil {
			labels[index] = decoded
		}
	}
	result := strings.Join(labels, ".")
	if trailingDot {
		result += "."
	}
	return result
}

func labelToASCII(label string) (string, error) {
	if isASCII(label) {
		for _, character := range label {
			if character <= 0x20 || character == 0x7f {
				return "", fmt.Errorf("contains whitespace or control characters")
			}
		}
		return label, nil
	}
	return idna.Lookup.ToASCII(label)
}

func isASCII(value string) bool {
	for len(value) > 0 {
		character, size := utf8.DecodeRuneInString(value)
		if character > 0x7f {
			return false
		}
		value = value[size:]
	}
	return true
}
