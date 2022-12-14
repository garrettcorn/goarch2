package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/gitlab"
)

type user struct {
	password []byte
	Name     string
}

var oauth = &oauth2.Config{
	ClientID:     "dcd95bd060cda29d6aff622f699f1ddacf5b2e59cd7c2d28eae00990ad43dd52",
	ClientSecret: "6f98b0cb2dca6dbfd0b4d7ddd82bd41427e517dbc4b15fa1a706d61b951b4745",
	Endpoint:     gitlab.Endpoint,
	RedirectURL:  "http://localhost:9090/oauth/gitlab/receive",
	Scopes:       []string{"openid", "email"},
}

// key is email, value is user
var db = map[string]user{}

// key is sessionid, value is email
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiration time
var oauthExp = map[string]time.Time{}

// key is uid from oauth provider; value is user id, eg, email
var oauthConnections = map[string]string{}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/oauth/gitlab/login", oGitlabLogin)
	// notice this is your "redirect" URL listed above in oauth2.Config
	http.HandleFunc("/oauth/gitlab/receive", oGitlabReceive)
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/gitlab/register", oGitlabRegister)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":9090", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var e string
	if sID != "" {
		e = sessions[sID]
	}

	var f string
	if user, ok := db[e]; ok {
		f = user.Name
	}

	errMsg := r.FormValue("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
	<h1>IF YOU HAVE A SESSION, HERE IS YOUR NAME: %s</h1>
	<h1>IF YOU HAVE A SESSION, HERE IS YOUR EMAIL: %s</h1>
	<h1>IF THERE IS ANY MESSAGE FOR YOU, HERE IT IS: %s</h1>
        <h1>REGISTER</h1>
		<form action="/register" method="POST">
		<label for="name">Name</label>
		<input type="text" name="name" placeholder="Name" id="name">
		<input type="email" name="e">
			<input type="password" name="p">
			<input type="submit">
        </form>
        <h1>LOG IN</h1>
        <form action="/login" method="POST">
            <input type="email" name="e">
			<input type="password" name="p">
			<input type="submit">
		</form>
        <h1>LOG IN WITH gitlab</h1>
        <form action="/oauth/gitlab/login" method="POST">
			<input type="submit" value="LOGIN WITH gitlab">
		</form>
		<h1>LOGOUT</h1>
		<form action="/logout" method="POST">
		<input type="submit" value="LOGOUT">
	</form>
	</body>
	</html>`, f, e, errMsg)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("name")
	if f == "" {
		msg := url.QueryEscape("your name name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
			msg := "there was an internal server error - evil laugh: hahahahaha"
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		log.Println("password", p)
		log.Println("bcrypted", bsp)
		db[e] = user{
			password: bsp,
			Name:     f,
		}
	} else {
		msg := "user already exists"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(db[e].password, []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err = createSession(e, w)
	if err != nil {
		log.Println("couldn't createSession in login", err)
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func createSession(e string, w http.ResponseWriter) error {
	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token, err := createToken(sUUID)
	if err != nil {
		return fmt.Errorf("couldn't createtoken in createSession %w", err)
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
		Path:  "/",
	}

	http.SetCookie(w, &c)
	return nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	delete(sessions, sID)

	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func oGitlabLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	id := uuid.New().String()
	oauthExp[id] = time.Now().Add(time.Hour)

	// here we redirect to gitlab at the AuthURL endpoint
	// adds state, scope, clientid
	http.Redirect(w, r, oauth.AuthCodeURL(id), http.StatusSeeOther)
}

func oGitlabReceive(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		msg := url.QueryEscape("state was empty in ogitlabReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// we got this code from gitlab
	code := r.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("code was empty in ogitlabReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	expT := oauthExp[state]
	if time.Now().After(expT) {
		msg := url.QueryEscape("oauth took too long time.now.after")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// exchange our code for a token
	// this uses the client secret also
	// the TokenURL is called
	// we get back a token
	t, err := oauth.Exchange(r.Context(), code)
	if err != nil {
		msg := url.QueryEscape("couldn't do oauth exchange: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	ts := oauth.TokenSource(r.Context(), t)
	c := oauth2.NewClient(r.Context(), ts)

	resp, err := c.Get("https://gitlab.com/oauth/userinfo")
	if err != nil {
		msg := url.QueryEscape("couldn't get at gitlab: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	// xb, _ := io.ReadAll(resp.Body)
	// log.Println(string(xb))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := url.QueryEscape("not a 200 resp code")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	type profileResponse struct {
		Email  string `json:"email"`
		Name   string `json:"name"`
		UserID string `json:"sub"`
	}

	var pr profileResponse

	err = json.NewDecoder(resp.Body).Decode(&pr)
	if err != nil {
		msg := url.QueryEscape("not able to decode json response")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// check to see if they have already registered at our site with this oauth2
	// key is uid from oauth provider; value is user id, eg, email
	eml, ok := oauthConnections[pr.UserID]

	if !ok {
		// not regiestered at our site yet with gitlab
		// register at our site with gitlab
		st, err := createToken(pr.UserID)
		if err != nil {
			log.Println("couldn't createToken in ogitlabReceive", err)
			msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
			http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
			return
		}

		uv := url.Values{}
		uv.Add("sst", st)
		uv.Add("name", pr.Name)
		uv.Add("email", pr.Email)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
		return
	}

	err = createSession(eml, w)
	if err != nil {
		log.Println("couldn't createSession in ogitlabReceive", err)
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + eml)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	sst := r.FormValue("sst")
	name := r.FormValue("name")
	email := r.FormValue("email")

	if sst == "" {
		log.Println("couldn't get sst in partialRegister")
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
		<form action="/oauth/gitlab/register" method="POST">
	
		<label for="Name">NAME</label>
		<input type="text" name="name" id="Name" value="%s">
	
		<label for="Email">EMAIL</label>
		<input type="text" name="email" id="Email" value="%s">
	
		<input type="hidden" value="%s" name="oauthID">
		
		<input type="submit">
		</form>
	</body>
	</html>`, name, email, sst)
}

func oGitlabRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("name")
	e := r.FormValue("email")
	oauthID := r.FormValue("oauthID")

	if f == "" {
		msg := url.QueryEscape("your name name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if oauthID == "" {
		log.Println("oauthID came through as empty at ogitlabRegister")
		msg := url.QueryEscape("your oauthID needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	gitlabUID, err := parseToken(oauthID)
	if err != nil {
		log.Println("parseToken at ogitlabRegister didn't parse")
		msg := url.QueryEscape("there was an issue. send us money so we can fix it.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	db[e] = user{
		Name: f,
	}

	// key is uid from oauth provider; value is user id, eg, email
	oauthConnections[gitlabUID] = e

	err = createSession(e, w)
	if err != nil {
		log.Println("couldn't CreateSession in ogitlabRegister", err)
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
