package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// content holds our static web server content.
//
//go:embed template/*
var content embed.FS

// JSON layout {"data":{"viewer":{"login":"garrettcorn","url":"https://github.com/garrettcorn","id":"MDQ6VXNlcjU5MTQ5NzY="}}}
type gitHubData struct {
	Data struct {
		Viewer struct {
			Login string `json:"login"`
			URL   string `json:"url"`
			ID    string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

var gitHubOathConfig = oauth2.Config{
	ClientID:     "119c8174bb8502390423",
	ClientSecret: "0ab8c08a8c5fbdef80bcb6da242d09293c0a1d46",
	Endpoint:     endpoints.GitHub,
	RedirectURL:  "http://localhost:9090/oauth2/receive",
	Scopes:       []string{"read:user"},
}

var gitHubLoginAttempts map[string]time.Time

func main() {
	// instantiate login attempt "db"
	gitHubLoginAttempts = map[string]time.Time{}

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOath)
	http.HandleFunc("/oauth2/receive", oauth2Receive)
	http.ListenAndServe(":9090", nil)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("index").ParseFS(content, "template/index.html")
	check(err)
	err = t.ExecuteTemplate(w, "index", "<script>alert('you have been pwned')</script>")
	check(err)
}

func oauth2Receive(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	loginTimeout := 1 * time.Minute

	if tv, ok := gitHubLoginAttempts[state]; ok {
		if time.Since(tv) < loginTimeout {
			token, err := gitHubOathConfig.Exchange(r.Context(), code)
			if err == nil {
				ts := gitHubOathConfig.TokenSource(r.Context(), token)
				client := oauth2.NewClient(r.Context(), ts)

				requestBody := strings.NewReader(`{"query": "query { viewer {login,url,id} }"}`)
				resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
				if err != nil {
					http.Error(w, "Couldn't get the user email", http.StatusInternalServerError)
					return
				}
				defer resp.Body.Close()

				var d gitHubData
				err = json.NewDecoder(resp.Body).Decode(&d)
				if err != nil {
					http.Error(w, "Unable to unmarshal github data", http.StatusInternalServerError)
					return
				}

				githubID := d.Data.Viewer.ID

				log.Println(githubID)
			}
		}
	}
}

func startGithubOath(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	gitHubLoginAttempts[uuid.String()] = time.Now()
	redirectUrl := gitHubOathConfig.AuthCodeURL(uuid.String())
	http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
}
