package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabiolb/fabio/auth/external"
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

	creds, err := makeCredentials(cfg)

	if err != nil {
		return nil, err
	}

	if creds != nil {
		opts = append(opts, grpc.WithTransportCredentials(creds))
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

func makeCredentials(cfg config.ExternalAuth) (credentials.TransportCredentials, error) {
	if !cfg.UseTLS {
		return nil, nil
	}

	clientCA, err := getCACert(cfg)

	if err != nil {
		return nil, err
	}

	return credentials.NewClientTLSFromCert(clientCA, cfg.ServerName), nil
}

func getCACert(cfg config.ExternalAuth) (*x509.CertPool, error) {
	caCert, _ := ioutil.ReadFile(cfg.ClientCAPath)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("error adding certificate to pool")
	}

	return pool, nil
}
