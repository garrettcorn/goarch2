package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"

	"github.com/garrettcorn/goarch2"
)

// id uuid to time oauth login started
var gitLabLoginStates map[string]time.Time = map[string]time.Time{}

// id email to user account
var userStore map[string]goarch2.User = map[string]goarch2.User{}

// id oauthid to user email
var oauthToUserStore map[string]string = map[string]string{}

// session uuid to user email
var sessions map[string]string = map[string]string{}

// secret signing key
var signingKey []byte = []byte("supersecretkey")

// oauth2
var gitLabConfig oauth2.Config = oauth2.Config{
	ClientID:     "dcd95bd060cda29d6aff622f699f1ddacf5b2e59cd7c2d28eae00990ad43dd52",
	ClientSecret: "6f98b0cb2dca6dbfd0b4d7ddd82bd41427e517dbc4b15fa1a706d61b951b4745",
	Scopes:       []string{"openid", "email"},
	Endpoint:     endpoints.GitLab,
	RedirectURL:  "http://localhost:9090/oauth/gitlab/receive",
}

func check(err error, msg string) {
	if err != nil {
		log.Fatal(msg+" : ", err)
	}
}

type openIdResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func gitLabReceive(w http.ResponseWriter, r *http.Request) {
	// http://localhost:9090/oauth/redirect?code=13f40f54f487f0b6bd876acb1daa4b632d8e5ae1883e6dc765c6106041ec67ef&state=state
	loginTimeout := 1 * time.Minute
	if time.Since(gitLabLoginStates[r.FormValue("state")]) < loginTimeout {
		// found state in
		code := r.FormValue("code")
		tok, err := gitLabConfig.Exchange(r.Context(), code)
		check(err, "unable to exchange oauth2 code")

		// ts := gitLabConfig.TokenSource(r.Context(), tok)
		// client := oauth2.NewClient(r.Context(), ts)

		client := gitLabConfig.Client(r.Context(), tok)
		resp, err := client.Get("https://gitlab.com/oauth/userinfo")
		check(err, "unable to query api")
		defer resp.Body.Close()

		// xb, _ := io.ReadAll(resp.Body)

		// log.Println(string(xb))

		d := openIdResponse{}
		err = json.NewDecoder(resp.Body).Decode(&d)
		check(err, "unable to decode response body")

		email, ok := oauthToUserStore[d.Sub]
		if !ok {
			// Oauth account not linked to a user account
			// assign test email for now
			timeout := time.Now().Add(1 * time.Minute)
			st := createToken("", string(d.Sub), d.Email, signingKey, timeout)

			uv := url.Values{}
			uv.Add("sst", st)
			uv.Add("name", d.Name)
			uv.Add("email", d.Email)

			http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
			return
		} else {
			err = createSession(w, email)
			check(err, "unable to create session for user")
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func createToken(sessionId, oauthId, email string, key []byte, timeout time.Time) string {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS512,
		myCustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(timeout)},
			ID:      sessionId,
			OauthId: oauthId,
			Email:   email,
		})
	ss, err := token.SignedString(key)
	check(err, "unable to sign token")
	return ss
}

func decryptToken(ss string, key []byte) *myCustomClaims {
	token, err := jwt.ParseWithClaims(ss, &myCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
	if err == nil && token.Valid {
		return token.Claims.(*myCustomClaims)
	}
	return &myCustomClaims{}
}

func createSession(w http.ResponseWriter, email string) error {
	sessionTimeout := time.Now().Add(1 * time.Minute)
	sessionId := uuid.New().String()

	ss := createToken(sessionId, "", email, signingKey, sessionTimeout)

	sessionCookie := http.Cookie{
		Name:    "session",
		Value:   ss,
		Path:    "/",
		Expires: sessionTimeout,
	}

	sessions[sessionId] = email
	http.SetCookie(w, &sessionCookie)
	return nil
}

func getSession(ss string) string {
	return decryptToken(ss, signingKey).ID
}

func gitLabLogin(w http.ResponseWriter, r *http.Request) {
	// https://gitlab.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&state=STATE&scope=REQUESTED_SCOPES
	// https://gitlab.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&state=STATE&scope=REQUESTED_SCOPES&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
	uuid := uuid.New().String()
	gitLabLoginStates[uuid] = time.Now()
	url := gitLabConfig.AuthCodeURL(uuid, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

type myCustomClaims struct {
	jwt.RegisteredClaims
	ID      string
	OauthId string
	Email   string
}

func encrypt(msg []byte, key []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	name := r.FormValue("name")
	sst := r.FormValue("sst")

	i, err := template.New("partialRegister").ParseFS(goarch2.Efs, goarch2.PartialRegisterFile, goarch2.HeaderFile, goarch2.RegisterFile)
	check(err, "unable to parse index file")
	err = i.ExecuteTemplate(
		w,
		"partialRegister",
		goarch2.PartialRegisterData{
			Header:   goarch2.HeaderData{Title: "Oauth2"},
			Register: goarch2.RegisterData{Action: "/register", Email: email, Sid: sst, Name: name},
		})
	check(err, "unable to execute partialRegister")
}

func index(w http.ResponseWriter, r *http.Request) {
	userMsg := "Not Logged In"
	var email string
	var oauthid string

	sc, err := r.Cookie("session")
	if err == nil {
		ss := sc.Value
		token := decryptToken(ss, signingKey)
		email = token.Email
		oauthid = token.OauthId
		if email != "" {
			userMsg = fmt.Sprintf("Logged In: %s", email)
		}
	} else {
		log.Println("cookie not found")
	}

	i, err := template.New("index").ParseFS(goarch2.Efs, goarch2.IndexFile, goarch2.HeaderFile, goarch2.GitLabFile, goarch2.LoggedInFile, goarch2.RegisterFile)
	check(err, "unable to parse index file")
	err = i.ExecuteTemplate(
		w,
		"index",
		goarch2.IndexData{
			Header:   goarch2.HeaderData{Title: "Oauth2"},
			GitLab:   goarch2.GitLabData{Action: "/oauth/gitlab/login"},
			LoggedIn: goarch2.LoggedInData{User: userMsg},
			Register: goarch2.RegisterData{Action: "/register", Email: email, Sid: oauthid},
		})
	check(err, "unable to execute index")
}

func register(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("password")
	e := r.FormValue("email")
	n := r.FormValue("name")
	sst := r.FormValue("sid")
	var id string

	if p != "" && e != "" {
		if sst != "" {
			t := decryptToken(sst, signingKey)
			id = t.ID
		}
		hp := encrypt([]byte(p), signingKey)
		userStore[e] = goarch2.User{
			Name:     n,
			Email:    e,
			Password: hp,
			ID:       id,
		}
		if id != "" {
			oauthToUserStore[id] = e
		}
		createSession(w, e)

	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func currentUser(w http.ResponseWriter, r *http.Request) {
	sc, err := r.Cookie("session")
	if err == nil {
		ss := sc.Value
		email := getSession(ss)
		if email != "" {
			id := userStore[email].ID
			w.Write([]byte(fmt.Sprintf("My email is: %v\nMy ID is: %v\n", email, id)))
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/gitlab/login", gitLabLogin)
	http.HandleFunc("/oauth/gitlab/receive", gitLabReceive)
	http.HandleFunc("/currentUser", currentUser)
	http.HandleFunc("/register", register)
	http.HandleFunc("/partial-register", partialRegister)
	http.ListenAndServe(":9090", nil)
}
