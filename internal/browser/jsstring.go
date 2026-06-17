package browser

import "encoding/json"

// jsString renders s as a JavaScript string literal that is safe to embed in a
// chromedp Evaluate expression. It uses JSON encoding (a JSON string is a valid
// JS string literal), so quotes, backslashes and control characters in s cannot
// break out of the literal and inject code. json.Marshal of a string never
// fails, so any encoding error is treated as the empty literal.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
