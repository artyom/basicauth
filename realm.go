// Package basicauth provides support for basic HTTP authentications scheme
// (http://tools.ietf.org/html/rfc2617#section-2).
//
// Here's a quick example:
//
//	package main
//
//	import (
//		"fmt"
//		"log"
//		"net/http"
//
//		"github.com/artyom/basicauth"
//	)
//
//	var realm *basicauth.Realm
//
//	func main() {
//		realm = basicauth.NewRealm("Restricted area")
//		realm.AddUser("Aladdin", "open sesame")
//		http.HandleFunc("/", authExample)
//		log.Fatal(http.ListenAndServe())
//	}
//
//	func authExample(w http.ResponseWriter, r *http.Request) {
//		username, err := realm.Check(r)
//		if err != nil {
//			if err != basicauth.NoAuth {
//				log.Printf("Authentication error: %s", err)
//			}
//			realm.Require(w)
//			return
//		}
//		fmt.Fprintf(w, "Hello, %s!\n", username)
//	}
package basicauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type Realm struct {
	sync.RWMutex
	// Authentication realm name
	Name string
	// ACL map: keys are usernames, values are passwords
	users map[string]string
}

// No authentication headers found in HTTP request
var NoAuth = errors.New("Authentication required")

// Check verifies whether request is allowed against current ACLs (realm
// users). Returned error would be of NoAuth type if no Authorization headers
// were found if request.
func (realm *Realm) Check(r *http.Request) (username string, err error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", NoAuth
	}
	if !strings.HasPrefix(hdr, "Basic ") {
		return "", fmt.Errorf("Unsupported authentication scheme")
	}
	b64data := strings.TrimPrefix(hdr, "Basic ")
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return "", fmt.Errorf("Failed to decode %q: %s", b64data, err)
	}
	credentials := strings.SplitN(string(data), ":", 2)
	if len(credentials) != 2 {
		return "", fmt.Errorf("Invalid credentials received: %q", data)
	}
	username = credentials[0]
	secret := credentials[1]
	realm.RLock()
	defer realm.RUnlock()
	if secretStored, ok := realm.users[username]; ok {
		if secretStored == secret {
			return username, nil
		}
	}
	return "", fmt.Errorf("No matching user/secret pair found")
}

// Require writes authentication headers to http.ResponseWriter, returns 401
// error code to user. You should normally return from request handler right
// after calling this function.
func (realm *Realm) Require(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm.Name))
	http.Error(w, "Authentication required", http.StatusUnauthorized)
	return
}

// Add user credentials to realm.
func (realm *Realm) AddUser(username, secret string) error {
	if len(username) == 0 || len(secret) == 0 {
		return fmt.Errorf("Both username and secret should be non-empty")
	}
	realm.Lock()
	defer realm.Unlock()
	realm.users[username] = secret
	return nil
}

// NewRealm returns new Realm object with given name.
func NewRealm(name string) *Realm {
	return &Realm{
		Name:  name,
		users: make(map[string]string),
	}
}