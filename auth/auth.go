package auth

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/fabiolb/fabio/config"
)

type AuthScheme interface {
	Authorized(request *http.Request, response http.ResponseWriter, dest *url.URL, service string) bool
}

func LoadAuthSchemes(cfg map[string]config.AuthScheme) (map[string]AuthScheme, error) {
	auths := map[string]AuthScheme{}
	for _, a := range cfg {
		switch a.Type {
		case "basic":
			b, err := newBasicAuth(a.Basic)
			if err != nil {
				return nil, err
			}
			auths[a.Name] = b
		case "external":
			e, err := newExternalAuth(a.External)
			if err != nil {
				return nil, err
			}
			auths[a.Name] = e
		default:
			return nil, fmt.Errorf("unknown auth type '%s'", a.Type)
		}
	}

	return auths, nil
}
