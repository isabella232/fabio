package auth

import (
	"log"
	"net/http"
	"net/url"

	"github.com/fabiolb/fabio/config"
	"github.com/tg123/go-htpasswd"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

// basic is an implementation of AuthScheme
type basic struct {
	realm   string
	secrets *htpasswd.HtpasswdFile
}

func newBasicAuth(cfg config.BasicAuth) (AuthScheme, error) {
	secrets, err := htpasswd.New(cfg.File, htpasswd.DefaultSystems, func(err error) {
		log.Println("[WARN] Error reading Htpasswd file: ", err)
	})

	if err != nil {
		return nil, err
	}

	return &basic{
		secrets: secrets,
		realm:   cfg.Realm,
	}, nil
}

func (b *basic) AuthorizedHTTP(request *http.Request, response http.ResponseWriter, _ *url.URL, _ string) bool {
	user, password, ok := request.BasicAuth()

	if !ok {
		response.Header().Set("WWW-Authenticate", "Basic realm=\""+b.realm+"\"")
		return false
	}

	return b.secrets.Match(user, password)
}

func (b *basic) AuthorizedGRPC(md metadata.MD, connInfo *stats.ConnTagInfo, URL *url.URL, fullMethod string, service string) bool {
	panic("not implemented")
}

func (b *basic) SupportedProto(proto string) bool {
	return proto == "http" || proto == "https"
}
