package browser

import "testing"

// TestJSStringEscapesInjection verifies that jsString produces a safe JS string
// literal: any quote/backslash/newline in the input must be escaped so it
// cannot break out of the literal and inject code. The output must be a valid
// JSON string (which is a valid JS string literal).
func TestJSStringEscapesInjection(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "07108025520188020001", `"07108025520188020001"`},
		{"sixdigit", "123456", `"123456"`},
		{"double_quote", `a"b`, `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"newline", "a\nb", `"a\nb"`},
		{"injection_attempt", `");alert(1);//`, `"\");alert(1);//"`},
		{"empty", "", `""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jsString(tc.in)
			if got != tc.want {
				t.Fatalf("jsString(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
