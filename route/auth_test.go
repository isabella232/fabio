package route

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/fabiolb/fabio/auth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

type testAuth struct {
	ok bool
}

func (t *testAuth) AuthorizedHTTP(r *http.Request, w http.ResponseWriter, dest *url.URL, service string) bool {
	return t.ok
}

func (t *testAuth) AuthorizedGRPC(md *metadata.MD, connInfo *stats.ConnTagInfo, dest *url.URL, fullMethod string, service string) bool {
	return t.ok
}

func (t *testAuth) SupportedProto(proto string) bool {
	return proto == "https"
}

type responseWriter struct {
	header  http.Header
	code    int
	written []byte
}

func (rw *responseWriter) Header() http.Header {
	return rw.header
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.written = append(rw.written, b...)
	return len(rw.written), nil
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.code = statusCode
}

func TestTarget_AuthorizedHTTP(t *testing.T) {
	tests := []struct {
		name        string
		authScheme  string
		authSchemes map[string]auth.AuthScheme
		out         bool
		proto       string
	}{
		{
			name:       "matches correct auth scheme",
			authScheme: "mybasic",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			out: true,
		},
		{
			name:       "returns true when scheme is empty",
			authScheme: "",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: false},
			},
			out: true,
		},
		{
			name:       "returns false when scheme is unknown",
			authScheme: "foobar",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			out: false,
		},
		{
			name:       "returns false when proto is not supported by auth scheme",
			authScheme: "foobar",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			proto: "foo",
			out:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proto == "" {
				tt.proto = "https"
			}

			target := &Target{
				AuthScheme: tt.authScheme,
				URL: &url.URL{
					Scheme: tt.proto,
				},
			}

			if got, want := target.AuthorizedHTTP(&http.Request{}, &responseWriter{}, tt.authSchemes), tt.out; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}

func TestTarget_AuthorizedGRPC(t *testing.T) {
	tests := []struct {
		name        string
		authScheme  string
		authSchemes map[string]auth.AuthScheme
		out         bool
		proto       string
	}{
		{
			name:       "matches correct auth scheme",
			authScheme: "mybasic",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			out: true,
		},
		{
			name:       "returns true when scheme is empty",
			authScheme: "",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: false},
			},
			out: true,
		},
		{
			name:       "returns false when scheme is unknown",
			authScheme: "foobar",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			out: false,
		},
		{
			name:       "returns false when proto is not supported by auth scheme",
			authScheme: "foobar",
			authSchemes: map[string]auth.AuthScheme{
				"mybasic": &testAuth{ok: true},
			},
			proto: "foo",
			out:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proto == "" {
				tt.proto = "https"
			}

			target := &Target{
				AuthScheme: tt.authScheme,
				URL: &url.URL{
					Scheme: tt.proto,
				},
			}

			if got, want := target.AuthorizedGRPC(&metadata.MD{}, &stats.ConnTagInfo{}, &stats.RPCTagInfo{}, tt.authSchemes), tt.out; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}
