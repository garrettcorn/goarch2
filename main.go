package main

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

//go:embed template
var efs embed.FS

// template files
var indexFile string = "template/index.html"
var headerFile string = "template/header.html"
var gitlabFile string = "template/gitlab.html"

// template data
type indexData struct {
	Header headerData
	GitLab gitLabData
}

type headerData struct {
	Title string
}

type gitLabData struct {
	Action string
}

// oauth2
// gitlab https://docs.gitlab.com/ee/api/graphql/reference/index.html
// to get current user Query.currentUser
// need the id https://docs.gitlab.com/ee/api/graphql/reference/index.html#usercore
// could be base64 encoded https://docs.gitlab.com/ee/api/graphql/reference/index.html#id
var gitLabConfig oauth2.Config = oauth2.Config{
	ClientID:     "dcd95bd060cda29d6aff622f699f1ddacf5b2e59cd7c2d28eae00990ad43dd52",
	ClientSecret: "6f98b0cb2dca6dbfd0b4d7ddd82bd41427e517dbc4b15fa1a706d61b951b4745",
	// Scopes:       []string{"read_user", "read_api", "openid", "profile", "email"},
	Scopes:      []string{"openid", "email"},
	Endpoint:    endpoints.GitLab,
	RedirectURL: "http://localhost:9090/oauth/redirect",
}

type gitLabRestApiUserResponse struct {
	ID              int         `json:"id"`
	Username        string      `json:"username"`
	Name            string      `json:"name"`
	State           string      `json:"state"`
	AvatarURL       string      `json:"avatar_url"`
	WebURL          string      `json:"web_url"`
	CreatedAt       time.Time   `json:"created_at"`
	Bio             string      `json:"bio"`
	Location        string      `json:"location"`
	PublicEmail     string      `json:"public_email"`
	Skype           string      `json:"skype"`
	Linkedin        string      `json:"linkedin"`
	Twitter         string      `json:"twitter"`
	WebsiteURL      string      `json:"website_url"`
	Organization    string      `json:"organization"`
	JobTitle        string      `json:"job_title"`
	Pronouns        interface{} `json:"pronouns"`
	Bot             bool        `json:"bot"`
	WorkInformation interface{} `json:"work_information"`
	Followers       int         `json:"followers"`
	Following       int         `json:"following"`
	IsFollowed      bool        `json:"is_followed"`
	LocalTime       interface{} `json:"local_time"`
	LastSignInAt    time.Time   `json:"last_sign_in_at"`
	ConfirmedAt     time.Time   `json:"confirmed_at"`
	LastActivityOn  string      `json:"last_activity_on"`
	Email           string      `json:"email"`
	ThemeID         int         `json:"theme_id"`
	ColorSchemeID   int         `json:"color_scheme_id"`
	ProjectsLimit   int         `json:"projects_limit"`
	CurrentSignInAt time.Time   `json:"current_sign_in_at"`
	Identities      []struct {
		Provider       string      `json:"provider"`
		ExternUID      string      `json:"extern_uid"`
		SamlProviderID interface{} `json:"saml_provider_id"`
	} `json:"identities"`
	CanCreateGroup                 bool        `json:"can_create_group"`
	CanCreateProject               bool        `json:"can_create_project"`
	TwoFactorEnabled               bool        `json:"two_factor_enabled"`
	External                       bool        `json:"external"`
	PrivateProfile                 bool        `json:"private_profile"`
	CommitEmail                    string      `json:"commit_email"`
	SharedRunnersMinutesLimit      int         `json:"shared_runners_minutes_limit"`
	ExtraSharedRunnersMinutesLimit interface{} `json:"extra_shared_runners_minutes_limit"`
}

func check(err error, msg string) {
	if err != nil {
		log.Fatal(msg+" : ", err)
	}
}

func oauthRedirect(w http.ResponseWriter, r *http.Request) {
	// http://localhost:9090/oauth/redirect?code=13f40f54f487f0b6bd876acb1daa4b632d8e5ae1883e6dc765c6106041ec67ef&state=state
	loginTimeout := 1 * time.Minute
	if time.Since(gitLabLoginStates[r.FormValue("state")]) < loginTimeout {
		// found state in
		code := r.FormValue("code")
		tok, err := gitLabConfig.Exchange(r.Context(), code)
		check(err, "unable to exchange oauth2 code")

		ts := gitLabConfig.TokenSource(r.Context(), tok)

		client := oauth2.NewClient(r.Context(), ts)
		// requestBody := strings.NewReader(`{"query": "query { currentUser { id,publicEmail,username,webUrl,webPath} }"}`)
		// resp, err := client.Post("https://gitlab.com/api/graphql", "application/json", requestBody)
		resp, err := client.Get("https://gitlab.com/oauth/userinfo")
		// resp, err := client.Get("https://gitlab.com/api/v4/user")
		check(err, "unable to query api")
		defer resp.Body.Close()

		xb, err := io.ReadAll(resp.Body)
		check(err, "unable to read the resp body")
		fmt.Printf("xb: %v\n", string(xb))

		// d := gitLabRestApiUserResponse{}
		// err = json.NewDecoder(resp.Body).Decode(&d)
		// check(err, "unable to json decode the response")

		// log.Printf("user.Id=%v\n", d.ID)

		// fmt.Printf("d: %v\n", d)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

var gitLabLoginStates map[string]time.Time = map[string]time.Time{}

func gitLabLogin(w http.ResponseWriter, r *http.Request) {
	// https://gitlab.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&state=STATE&scope=REQUESTED_SCOPES
	// https://gitlab.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&state=STATE&scope=REQUESTED_SCOPES&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
	uuid := uuid.New().String()
	gitLabLoginStates[uuid] = time.Now()
	url := gitLabConfig.AuthCodeURL(uuid, oauth2.AccessTypeOffline)
	log.Println(url)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func index(w http.ResponseWriter, r *http.Request) {
	i, err := template.New("index").ParseFS(efs, indexFile, headerFile, gitlabFile)
	check(err, "unable to parse index file")
	err = i.ExecuteTemplate(
		w,
		"index",
		indexData{
			Header: headerData{Title: "Oauth2"},
			GitLab: gitLabData{Action: "/oauth/gitlab/login"}})
	check(err, "unable to execute index")

	log.Println(gitLabConfig.Endpoint.AuthURL)
	log.Println(gitLabConfig.Endpoint.TokenURL)
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/gitlab/login", gitLabLogin)
	http.HandleFunc("/oauth/redirect", oauthRedirect)
	http.ListenAndServe(":9090", nil)
}
