package auth

import "net/http"

type external struct {

}

func (e *external) Authorized(request *http.Request, response http.ResponseWriter) bool {
	return true
}