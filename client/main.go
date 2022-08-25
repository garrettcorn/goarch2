package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string
	Password []byte
}

type Session struct {
	Id        string
	Email     string
	ExpiresAt time.Time
}

type SessionStore interface {
	Add(s Session)
	Remove(id string)
	Get(id string) (Session, error)
}

type Storage interface {
	SaveUser(u User) error
	GetUser(username string) User
}

type MemorySessionStore struct {
	sessionStore map[string]Session
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessionStore: map[string]Session{},
	}
}

func (ss *MemorySessionStore) Add(s Session) {
	ss.sessionStore[s.Id] = s
}

func (ss *MemorySessionStore) Remove(id string) {
	delete(ss.sessionStore, id)
}

func (ss MemorySessionStore) Get(id string) (Session, error) {
	if _, ok := ss.sessionStore[id]; ok {
		if time.Now().Before(ss.sessionStore[id].ExpiresAt) {
			return ss.sessionStore[id], nil
		} else {
			delete(ss.sessionStore, id)
		}
	}
	return Session{}, fmt.Errorf("session not found")
}

type MemoryStore struct {
	store map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		store: map[string][]byte{},
	}
}

var ErrUserAlreadyRegistered = errors.New("MemoryStore: user aleady registered")

func (s *MemoryStore) SaveUser(u User) error {
	if s.store[u.Email] == nil {
		s.store[u.Email] = []byte(u.Password)
		return nil
	}
	return ErrUserAlreadyRegistered
}

func (s *MemoryStore) GetUser(username string) User {
	return User{Email: username, Password: s.store[username]}
}

func index(w http.ResponseWriter, r *http.Request) {
	var loggedInText string
	c, err := r.Cookie("session")
	if err != nil {
		log.Println("index unable to get session cookie: " + err.Error())
	} else {
		ps, err := parseToken(c.Value, key)
		if err != nil {
			log.Println("index unable to parse the session token: " + err.Error())
		} else {
			s, err := sessionStore.Get(ps)
			if err != nil {
				log.Println("index unable to get session from session store: " + err.Error())
			} else {
				loggedInText = "Logged in as: " + s.Email
			}
		}
	}

	statusMsg := r.FormValue("statusMsg")
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Index</title>
</head>
<body>
	<h2>` + loggedInText + `</h2>
	<h2>Register</h2>
    <form action="/register" method="post" class="form-example">
        <div class="form-example">
          <label for="username">Enter your username: </label>
          <input type="text" name="username" id="username" required>
        </div>
        <div class="form-example">
            <label for="password">Enter your password: </label>
            <input type="password" name="password" id="password" required>
          </div>
        <div class="form-example">
          <input type="submit" value="Register">
        </div>
    </form>
	<h2>Login</h2>
    <form action="/login" method="post" class="form-example">
        <div class="form-example">
          <label for="username">Enter your username: </label>
          <input type="text" name="username" id="username" required>
        </div>
        <div class="form-example">
            <label for="password">Enter your password: </label>
            <input type="password" name="password" id="password" required>
          </div>
        <div class="form-example">
          <input type="submit" value="Login">
        </div>
    </form>
	<p>` + statusMsg + `</p>
</body>
</html>`
	w.Write([]byte(html))
}

func encrypt(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		statusMsg := url.QueryEscape("method needs to be post")
		http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != "" && password != "" {
		ePassword, err := encrypt([]byte(password))
		if err != nil {
			statusMsg := url.QueryEscape("unable to encrypt password")
			http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
			return
		}
		err = storage.SaveUser(User{Email: username, Password: ePassword})
		if err != nil {
			statusMsg := url.QueryEscape("unable to save user")
			http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
			return
		}
		uuid, err := uuid.NewUUID()
		if err != nil {
			statusMsg := url.QueryEscape("unable to create uuid for user")
			http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
			return
		}
		id := uuid.String()
		expAt := time.Now().Add(5 * time.Second)
		sessionStore.Add(Session{
			Id:        id,
			Email:     username,
			ExpiresAt: expAt,
		})
		signedSession, err := createToken([]byte(id), key)
		if err != nil {
			statusMsg := url.QueryEscape("unable to sign session")
			http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
			return
		} else {
			http.SetCookie(w,
				&http.Cookie{
					Name:    "session",
					Value:   signedSession,
					Expires: expAt,
				})
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		statusMsg := url.QueryEscape("method needs to be post")
		http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != "" && password != "" {
		u := storage.GetUser(username)
		fmt.Printf("password: %v\n", password)
		fmt.Printf("u.Password: %v\n", u.Password)
		if bcrypt.CompareHashAndPassword(u.Password, []byte(password)) == nil {
			statusMsg := url.QueryEscape("login successful")

			uuid, err := uuid.NewUUID()
			if err != nil {
				statusMsg := url.QueryEscape("unable to create uuid for user")
				http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
				return
			}
			id := uuid.String()
			expAt := time.Now().Add(5 * time.Second)
			sessionStore.Add(Session{
				Id:        id,
				Email:     username,
				ExpiresAt: expAt,
			})
			signedSession, err := createToken([]byte(id), key)
			if err != nil {
				statusMsg := url.QueryEscape("unable to sign session")
				http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
				return
			} else {
				http.SetCookie(w,
					&http.Cookie{
						Name:    "session",
						Value:   signedSession,
						Expires: expAt,
					})
			}

			http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
			return
		} else {
			log.Println("faled login attempt from:", r.RemoteAddr)
		}
	}
	statusMsg := url.QueryEscape("login failed")
	http.Redirect(w, r, "/?statusMsg="+statusMsg, http.StatusSeeOther)
}

func hmacSign(msg []byte, key []byte) (string, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return "", fmt.Errorf("hmacSign: unable to write msg to hash. %w", err)
	}
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

func hmacCheck(msg, sig, key []byte) bool {
	tempSig, err := hmacSign(msg, key)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(tempSig), sig)
}

func createToken(sid, key []byte) (string, error) {
	sig, err := hmacSign(sid, key)
	if err != nil {
		return "", fmt.Errorf("cToken: unable to hmacSign %s, because %s", sid, err)
	}
	return string(sig) + "|" + string(sid), nil
}

func parseToken(ss string, key []byte) (string, error) {
	sep := "|"
	xs := strings.SplitN(ss, sep, 2)
	if len(xs) != 2 {
		return "", fmt.Errorf("length not equal to 2")
	}
	sig := xs[0]
	sid := xs[1]
	if hmacCheck([]byte(sid), []byte(sig), key) {
		return sid, nil
	}
	return "", fmt.Errorf("unable to parse token")
}

var storage Storage
var sessionStore SessionStore
var key []byte

func main() {
	// setup backend
	storage = NewMemoryStore()
	sessionStore = NewMemorySessionStore()
	key = []byte("MySuperSecretKey")

	// routes
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	// start server
	log.Panic(http.ListenAndServe(":9090", nil))
}
