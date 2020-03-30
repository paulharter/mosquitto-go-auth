package backends

import (
	"fmt"
	"net/url"
	"strings"
	log "github.com/sirupsen/logrus"
	"github.com/pkg/errors"
	jwt "github.com/dgrijalva/jwt-go"
)

type Ishiki struct {
	UserUri         string
	Host            string
	Port            string
	WithTLS         bool
	VerifyPeer      bool
	Secret          string
	ParamsMode      string
	ResponseMode    string
	UserField 		string
}

func NewIshiki(authOpts map[string]string, logLevel log.Level) (Ishiki, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var ishiki = Ishiki{
		WithTLS:      false,
		VerifyPeer:   false,
		ResponseMode: "status",
		ParamsMode:   "json",
		UserField:    "Subject",
	}

    missingOpts := ""
    remoteOk := true

    if responseMode, ok := authOpts["ishiki_response_mode"]; ok {
        if responseMode == "text" || responseMode == "json" {
            ishiki.ResponseMode = responseMode
        }
    }

    if paramsMode, ok := authOpts["ishiki_params_mode"]; ok {
        if paramsMode == "form" {
            ishiki.ParamsMode = paramsMode
        }
    }

    if userUri, ok := authOpts["ishiki_getuser_uri"]; ok {
        ishiki.UserUri = userUri
    } else {
        remoteOk = false
        missingOpts += " ishiki_getuser_uri"
    }

    if hostname, ok := authOpts["ishiki_host"]; ok {
        ishiki.Host = hostname
    } else {
        remoteOk = false
        missingOpts += " ishiki_host"
    }

    if port, ok := authOpts["ishiki_port"]; ok {
        ishiki.Port = port
    } else {
        remoteOk = false
        missingOpts += " ishiki_port"
    }

    if withTLS, ok := authOpts["ishiki_with_tls"]; ok && withTLS == "true" {
        ishiki.WithTLS = true
    }

    if verifyPeer, ok := authOpts["ishiki_verify_peer"]; ok && verifyPeer == "true" {
        ishiki.VerifyPeer = true
    }

    if !remoteOk {
        return ishiki, errors.Errorf("Ishiki backend error: missing options%s.\n", missingOpts)
    }

	return ishiki, nil
}

//GetUser authenticates a given user.
func (o Ishiki) GetUser(token, password string) bool {

    var dataMap map[string]interface{}
    var urlValues = url.Values{}
    return jwtRequest(o.Host, o.UserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
}

//GetSuperuser checks if the given user is a superuser.
func (o Ishiki) GetSuperuser(token string) bool {

    return false
}


//CheckAcl checks user authorization.
func (o Ishiki) CheckAcl(token, topic, clientid string, acc int32) bool {

    claims, err := o.getClaims(token)

	if err != nil {
		log.Debugf("getClaims error: %s\n", err)
		return false
	}

	var allowed = strings.HasPrefix(topic, fmt.Sprintf("%s/", claims.Subject))
    if !allowed {
        log.Debugf("Redis check acl error: %s %s", topic, claims.Subject)
    }

	return allowed
}

//GetName returns the backend's name
func (o Ishiki) GetName() string {
	return "Ishiki"
}

func (o Ishiki) getClaims(tokenStr string) (*Claims, error) {

	jwtToken, _, err := new(jwt.Parser).ParseUnverified(tokenStr, &Claims{})

	if err != nil {
		log.Debugf("jwt parse error: %s\n", err)
		return nil, err
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok {
		// no need to use a static error, this should never happen
		log.Debugf("api/auth: expected *Claims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}

func (o Ishiki) Halt() {
}
