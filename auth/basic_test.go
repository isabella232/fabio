package auth

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/fabiolb/fabio/config"
	"github.com/fabiolb/fabio/uuid"
)

type responseWriter struct {
	header  http.Header
	code    int
	written []byte
}

func (rw *responseWriter) Header() http.Header {
	if rw.header == nil {
		rw.header = map[string][]string{}
	}
	return rw.header
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.written = append(rw.written, b...)
	return len(rw.written), nil
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.code = statusCode
}

func createBasicAuthFile(contents string) (string, error) {
	dir, err := ioutil.TempDir("", "basicauth")

	if err != nil {
		return "", fmt.Errorf("could not create temp dir: %s", err)
	}

	filename := fmt.Sprintf("%s/%s", dir, uuid.NewUUID())

	err = ioutil.WriteFile(filename, []byte(contents), 0666)

	if err != nil {
		return "", fmt.Errorf("could not write password file: %s", err)
	}

	return filename, nil
}

func createBasicAuth(user string, password string) (AuthScheme, error) {
	contents := fmt.Sprintf("%s:%s", user, password)

	filename, err := createBasicAuthFile(contents)

	a, err := newBasicAuth(config.BasicAuth{
		File:  filename,
		Realm: "testrealm",
	})

	if err != nil {
		return nil, fmt.Errorf("could not create basic auth: %s", err)
	}

	return a, nil
}

func TestNewBasicAuth(t *testing.T) {

	t.Run("should create a basic auth scheme from the supplied config", func(t *testing.T) {
		filename, err := createBasicAuthFile("foo:bar")

		if err != nil {
			t.Error(err)
		}

		_, err = newBasicAuth(config.BasicAuth{
			File: filename,
		})

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("should log a warning when credentials are malformed", func(t *testing.T) {
		filename, err := createBasicAuthFile("foosdlijdgohdgdbar")

		if err != nil {
			t.Error(err)
		}

		_, err = newBasicAuth(config.BasicAuth{
			File: filename,
		})

		if err != nil {
			t.Error(err)
		}
	})
}

func TestBasic_Authorised(t *testing.T) {
	basicAuth, err := createBasicAuth("foo", "bar")
	creds := []byte("foo:bar")

	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		req  *http.Request
		res  http.ResponseWriter
		out  bool
	}{
		{
			"correct credentials should be authorized",
			&http.Request{
				Header: http.Header{
					"Authorization": []string{fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(creds))},
				},
			},
			&responseWriter{},
			true,
		},
		{
			"incorrect credentials should not be authorized",
			&http.Request{
				Header: http.Header{
					"Authorization": []string{fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("baz:blarg")))},
				},
			},
			&responseWriter{},
			false,
		},
		{
			"missing Authorization header should not be authorized",
			&http.Request{
				Header: http.Header{},
			},
			&responseWriter{},
			false,
		},
		{
			"malformed Authorization header should not be authorized",
			&http.Request{
				Header: http.Header{
					"Authorization": []string{"malformed"},
				},
			},
			&responseWriter{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := basicAuth.Authorized(tt.req, tt.res), tt.out; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}

func TestBasic_Authorized_should_set_www_realm_header(t *testing.T) {
	basicAuth, err := createBasicAuth("foo", "bar")

	if err != nil {
		t.Fatal(err)
	}

	rw := &responseWriter{}

	_ = basicAuth.Authorized(&http.Request{Header: http.Header{}}, rw)

	got := rw.Header().Get("WWW-Authenticate")
	want := "Basic realm=\"testrealm\""

	if strings.Compare(got, want) != 0 {
		t.Errorf("got '%s', want '%s'", got, want)
	}
}
