package dnsname

import "testing"

func TestToASCIIAndUnicode(t *testing.T) {
	tests := map[string]string{
		"灵":         "xn--5nx.",
		"灵.":        "xn--5nx.",
		"例子。测试":     "xn--fsqu00a.xn--0zwm56d.",
		"_wallet.灵": "_wallet.xn--5nx.",
		"XN--5NX":   "xn--5nx.",
	}
	for input, want := range tests {
		got, err := ToASCII(input)
		if err != nil {
			t.Fatalf("ToASCII(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ToASCII(%q) = %q, want %q", input, got, want)
		}
	}
	if got := ToUnicode("xn--5nx."); got != "灵." {
		t.Fatalf("ToUnicode() = %q", got)
	}
}

func TestToASCIIRejectsInvalidNames(t *testing.T) {
	for _, input := range []string{"example..org", "bad label.example"} {
		if _, err := ToASCII(input); err == nil {
			t.Fatalf("ToASCII(%q) succeeded", input)
		}
	}
}
