package awssecretsmanager

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeXMLError(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><ErrorResponse><Errors><Error><Code>InvalidClientTokenId</Code><Message>bad token</Message></Error></Errors></ErrorResponse>`
	res := &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(xmlBody))}
	normalizeXMLError(res)
	b, _ := io.ReadAll(res.Body)
	if res.Header.Get("X-Amzn-Errortype") != "InvalidClientTokenId" || !bytes.Contains(b, []byte(`"__type":"InvalidClientTokenId"`)) {
		t.Fatalf("not normalized: %s %v", b, res.Header)
	}
	single := `<Error><Code>AccessDenied</Code><Message>no</Message></Error>`
	res = &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(single))}
	normalizeXMLError(res)
	if res.Header.Get("X-Amzn-Errortype") != "AccessDenied" {
		t.Fatalf("single-error form not normalized")
	}
	for _, body := range []string{"plain text", "<html>oops</html>", ""} {
		res = &http.Response{StatusCode: 500, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
		normalizeXMLError(res)
		got, _ := io.ReadAll(res.Body)
		if string(got) != body || res.Header.Get("X-Amzn-Errortype") != "" {
			t.Fatalf("body %q changed to %q", body, got)
		}
	}
	res = &http.Response{StatusCode: 400, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(`{"__type":"X"}`))}
	normalizeXMLError(res)
	if got, _ := io.ReadAll(res.Body); string(got) != `{"__type":"X"}` {
		t.Fatalf("json body changed")
	}
}
