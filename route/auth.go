package route

import (
	"log"
	"net/http"

	"github.com/fabiolb/fabio/auth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

func (t *Target) AuthorizedHTTP(r *http.Request, w http.ResponseWriter, authSchemes map[string]auth.AuthScheme) bool {
	if t.AuthScheme == "" {
		return true
	}

	scheme := authSchemes[t.AuthScheme]

	if scheme == nil {
		log.Printf("[ERROR] unknown auth scheme '%s'\n", t.AuthScheme)
		return false
	}

	if !scheme.SupportedProto(t.URL.Scheme) {
		log.Printf("[ERROR] proto '%s' is not supported for auth scheme '%s'", t.URL.Scheme, t.AuthScheme)
		return false
	}

	return scheme.AuthorizedHTTP(r, w, t.URL, t.Service)
}

func (t *Target) AuthorizedGRPC(md metadata.MD, connInfo *stats.ConnTagInfo, rpcInfo *stats.RPCTagInfo, authSchemes map[string]auth.AuthScheme) bool {
	if t.AuthScheme == "" {
		return true
	}

	scheme := authSchemes[t.AuthScheme]

	if scheme == nil {
		log.Printf("[ERROR] unknown auth scheme '%s'\n", t.AuthScheme)
		return false
	}

	if !scheme.SupportedProto(t.URL.Scheme) {
		log.Printf("[ERROR] proto '%s' is not supported for auth scheme '%s'", t.URL.Scheme, t.AuthScheme)
		return false
	}

	return scheme.AuthorizedGRPC(md, connInfo, t.URL, rpcInfo.FullMethodName, t.Service)
}
