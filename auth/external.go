package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/fabiolb/fabio/auth/external"
	"github.com/fabiolb/fabio/cert"
	"github.com/fabiolb/fabio/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type external struct {
	grpc fabio_auth_external.AuthorizationClient
}

func newExternalAuth(cfg config.ExternalAuth) (*external, error) {
	ctx := context.Background()

	opts := []grpc.DialOption{}

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

func (e *external) Authorized(request *http.Request, response http.ResponseWriter, dest *url.URL, service string) bool {
	ctx := context.Background()

	body, err := ioutil.ReadAll(request.Body)
	request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	headers := map[string]string{}

	for k := range request.Header {
		headers[k] = request.Header.Get(k)
	}

	checkRequest := &fabio_auth_external.CheckRequest{
		Headers: headers,
		Body:    body,
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
