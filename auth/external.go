package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabiolb/fabio/auth/external"
	"github.com/fabiolb/fabio/cert"
	"github.com/fabiolb/fabio/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

type external struct {
	grpc fabio_auth_external.AuthorizationClient
}

func newExternalAuth(cfg config.ExternalAuth) (AuthScheme, error) {
	ctx := context.Background()

	opts := []grpc.DialOption{
		grpc.WithBackoffMaxDelay(time.Second * 1),
	}

	tlscfg, err := makeTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	if tlscfg != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlscfg)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	conn, err := grpc.DialContext(ctx, cfg.Addr, opts...)
	if err != nil {
		return nil, err
	}

	return &external{
		grpc: fabio_auth_external.NewAuthorizationClient(conn),
	}, nil
}

func (e *external) AuthorizedHTTP(request *http.Request, response http.ResponseWriter, dest *url.URL, service string) bool {
	ctx := context.Background()

	headers := map[string]string{}

	for k := range request.Header {
		headers[k] = request.Header.Get(k)
	}

	checkRequest := &fabio_auth_external.CheckRequest{
		Headers: headers,
		Source: &fabio_auth_external.Source{
			RemoteAddr: request.RemoteAddr,
			Url:        request.URL.String(),
		},
		Destination: &fabio_auth_external.Destination{
			Service: service,
			Url:     dest.String(),
		},
	}

	res, err := e.grpc.Check(ctx, checkRequest)

	if err != nil {
		log.Println("[WARN] external-auth: got an error from the auth service ", err)
		return false
	}

	return res.Ok
}

func (e *external) AuthorizedGRPC(md metadata.MD, connInfo *stats.ConnTagInfo, dest *url.URL, fullMethod string, service string) bool {
	ctx := context.Background()

	headers := map[string]string{}

	for k := range md {
		headers[k] = strings.Join(md.Get(k), " ")
	}

	// build the source url (i.e. the url that the request came in on)
	_, sourcePort, _ := net.SplitHostPort(connInfo.LocalAddr.String())
	sourceUrl := fmt.Sprintf("%s:%s%s", strings.Join(md.Get(":authority"), " "), sourcePort, fullMethod)

	checkRequest := &fabio_auth_external.CheckRequest{
		Headers: headers,
		Source: &fabio_auth_external.Source{
			RemoteAddr: connInfo.RemoteAddr.String(),
			Url:        sourceUrl,
		},
		Destination: &fabio_auth_external.Destination{
			Service: service,
			Url:     dest.String(),
		},
	}

	res, err := e.grpc.Check(ctx, checkRequest)

	if err != nil {
		log.Println("[WARN] external-auth: got an error from the auth service ", err)
		return false
	}

	return res.Ok
}

func (e *external) SupportedProto(proto string) bool {
	return proto == "http" || proto == "https" ||
		proto == "grpc" || proto == "grpcs"
}

func makeTLSConfig(cfg config.ExternalAuth) (*tls.Config, error) {
	if cfg.CertSource.Name == "" {
		return nil, nil
	}
	src, err := cert.NewSource(cfg.CertSource)
	if err != nil {
		return nil, fmt.Errorf("Failed to create cert source %s. %s", cfg.CertSource.Name, err)
	}
	tlscfg, err := cert.TLSConfig(src, cfg.StrictMatch, cfg.TLSMinVersion, cfg.TLSMaxVersion, cfg.TLSCiphers)
	if err != nil {
		return nil, fmt.Errorf("[FATAL] Failed to create TLS config for cert source %s. %s", cfg.CertSource.Name, err)
	}

	tlscfg.InsecureSkipVerify = cfg.TLSSkipVerify

	return tlscfg, nil
}
