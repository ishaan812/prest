package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prest/prest/config"
	pctx "github.com/prest/prest/context"
	"github.com/prest/prest/controllers/auth"
	"github.com/urfave/negroni/v3"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	ErrJWTParseFail = errors.New("failed JWT token parser")
	ErrJWTValidate  = errors.New("failed JWT claims validated")
)

// HandlerSet add content type header
func HandlerSet() negroni.Handler {
	return negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		format := r.URL.Query().Get("_renderer")
		recorder := httptest.NewRecorder()
		negroniResp := negroni.NewResponseWriter(recorder)
		next(negroniResp, r)
		renderFormat(w, recorder, format)
	})
}

// SetTimeoutToContext adds the configured timeout in seconds to the request context
//
// By default it is 60 seconds, can be modified to a different value
func SetTimeoutToContext() negroni.Handler {
	return negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		next(rw, r.WithContext(context.WithValue(r.Context(), pctx.HTTPTimeoutKey, config.PrestConf.HTTPTimeout))) // nolint
	})
}

// AuthMiddleware handle request token validation
func AuthMiddleware() negroni.Handler {
	return negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		match, err := MatchURL(r.URL.String())
		if err != nil {
			http.Error(rw, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
			return
		}
		if config.PrestConf.AuthEnabled && !match {
			// extract authorization token
			token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
			if token == "" {
				err := fmt.Errorf("authorization token is empty")
				http.Error(rw, err.Error(), http.StatusUnauthorized)
				return
			}

			tok, err := jwt.ParseSigned(token)
			if err != nil {
				http.Error(rw, ErrJWTParseFail.Error(), http.StatusUnauthorized)
				return
			}
			claims := auth.Claims{}
			if err := tok.Claims([]byte(config.PrestConf.JWTKey), &claims); err != nil {
				http.Error(rw, err.Error(), http.StatusUnauthorized)
				return
			}
			if err := Validate(claims); err != nil {
				http.Error(rw, err.Error(), http.StatusUnauthorized)
				return
			}

			// pass user_info to the next handler
			ctx := r.Context()
			ctx = context.WithValue(ctx, pctx.UserInfoKey, claims.UserInfo)
			r = r.WithContext(ctx)
		}

		// if auth isn't enabled
		next(rw, r)
	})
}

// Validate claims
func Validate(c auth.Claims) error {
	if c.Expiry != nil && time.Now().After(c.Expiry.Time()) {
		return ErrJWTValidate
	}
	if c.NotBefore != nil && time.Now().Before(c.NotBefore.Time()) {
		return ErrJWTValidate
	}
	return nil
}

// AccessControl is a middleware to handle permissions on tables in pREST
func AccessControl() negroni.Handler {
	return negroni.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request, next http.HandlerFunc) {
		mapPath := getVars(rq.URL.Path)
		if mapPath == nil {
			next(rw, rq)
			return
		}

		permission := permissionByMethod(rq.Method)
		if permission == "" {
			next(rw, rq)
			return
		}

		if config.PrestConf.Adapter.TablePermissions(mapPath["table"], permission) {
			next(rw, rq)
			return
		}

		err := fmt.Errorf("required authorization to table %s", mapPath["table"])
		http.Error(rw, err.Error(), http.StatusUnauthorized)
	})
}

func CustomMiddleware() negroni.Handler {
	return negroni.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request, next http.HandlerFunc) {
		authHeader := rq.Header.Get("Authorization")
		if authHeader == "" {
			SendErrorResponse(rw, 401, "No Auth Token Found")
			return
		}
		tokenString := authHeader[len("Bearer "):]
		token, err := VerifyToken(tokenString, []byte(config.PrestConf.JWTKey))
		if err != nil {
			return
		}
		fmt.Println("token => ", token.TenantID, token.Expiry)
		ctx := context.WithValue(rq.Context(), "tenantId", token.TenantID)
		rq = rq.WithContext(ctx)
		next(rw, rq)
	})
}

// JwtMiddleware check if actual request have JWT
func JwtMiddleware(key string, JWKSet string) negroni.Handler {
	return negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		match, err := MatchURL(r.URL.String())
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
			return
		}
		if match {
			next(w, r)
			return
		}

		// extract authorization token
		token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
		if token == "" {
			err := fmt.Errorf("authorization token is empty")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		tok, err := jwt.ParseSigned(token)
		if err != nil {
			http.Error(w, ErrJWTParseFail.Error(), http.StatusUnauthorized)
			return
		}
		out := auth.Claims{}
		var rawkey interface{} = []byte(key)

		if JWKSet != "" {
			parsedJWKSet, err := jwk.ParseString(JWKSet)
			if err != nil {
				err := fmt.Errorf("failed to parse JWKSet JSON string: %v", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			for it := parsedJWKSet.Keys(context.Background()); it.Next(context.Background()); {
				pair := it.Pair()
				key := pair.Value.(jwk.Key)

				if key.KeyID() == tok.Headers[0].KeyID {
					if err := key.Raw(&rawkey); err != nil {
						err := fmt.Errorf("failed to create public key: %s", err)
						http.Error(w, err.Error(), http.StatusUnauthorized)
						return
					}
				}
			}
			//Check if rawkey is empty
			if key, ok := rawkey.(string); ok {
				if key == "" {
					err := fmt.Errorf("the token's key was not found in the JWKS")
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
			}
		}

		if err := tok.Claims(rawkey, &out); err != nil {
			http.Error(w, ErrJWTValidate.Error(), http.StatusUnauthorized)
			return
		}
		if err := Validate(out); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

// Cors middleware
//
// Deprecated: we'll use github.com/rs/cors instead
func Cors(origin []string, headers []string) negroni.Handler {
	return negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(headerAllowOrigin, strings.Join(origin, ","))
		w.Header().Set(headerAllowCredentials, strconv.FormatBool(true))
		if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set(headerAllowMethods, strings.Join(defaultAllowMethods, ","))
			w.Header().Set(headerAllowHeaders, strings.Join(headers, ","))
			if allowed := checkCors(r, origin); !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	})
}

func ExposureMiddleware() negroni.Handler {
	return negroni.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request, next http.HandlerFunc) {
		url := rq.URL.Path
		exposeConf := config.PrestConf.ExposeConf

		if strings.HasPrefix(url, "/databases") && !exposeConf.DatabaseListing {
			http.Error(rw, "unauthorized listing", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(url, "/tables") && !exposeConf.TableListing {
			http.Error(rw, "unauthorized listing", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(url, "/schemas") && !exposeConf.SchemaListing {
			http.Error(rw, "unauthorized listing", http.StatusUnauthorized)
			return
		}

		next(rw, rq)
	})
}

type Error struct {
	Message     string `json:"message"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

type Response struct {
	Error *Error      `json:"error"`
	Data  interface{} `json:"data"`
}

func SendErrorResponse(w http.ResponseWriter, statusCode int, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(&Response{
		Error: &Error{
			Description: desc,
		},
		Data: nil,
	})
}

// CustomClaims represents the custom claims in your JWT
type CustomClaims struct {
	TenantID string           `json:"tenantId"`
	Expiry   *jwt.NumericDate `json:"exp,omitempty"`
}

// VerifyToken verifies the JWT token using the provided key
func VerifyToken(tokenString string, key []byte) (*CustomClaims, error) {
	tok, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims := CustomClaims{}
	if err := tok.Claims(key, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	if claims.Expiry != nil && time.Now().After(claims.Expiry.Time()) {
		return nil, fmt.Errorf("token has expired")
	}

	return &claims, nil
}
