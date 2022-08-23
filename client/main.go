package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Users    []Person `json:"Users"`
	Port     string   `json:"Port"`
	Filename string   `json:"-"`
}

type Person struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

func (p Person) String() string {
	return fmt.Sprintf("First name is: %s. Last name is: %s.", p.First, p.Last)
}

func (c Config) Write() (n int, err error) {
	xb, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Fatalf("Unable to marshall. %v\n", err)
	}
	f, err := os.Create(c.Filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if err != nil {
		return 0, fmt.Errorf("unable to write config file. %e", err)
	}
	return f.Write(xb)
}

func (c *Config) Read() error {
	f, err := os.Open(c.Filename)
	if err != nil {
		return fmt.Errorf("unable to read config. %e", err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	return d.Decode(c)
}

func (c *Config) SetDefaults() {
	if c.Filename == "" {
		c.Filename = "config.json"
	}
	if c.Port == "" {
		c.Port = ":4040"
	}
	if len(c.Users) == 0 {
		c.Users = []Person{
			{
				First: "John",
				Last:  "Doe",
			},
			{
				First: "Jane",
				Last:  "Doe",
			},
		}
	}
}

func encodepp(w http.ResponseWriter, r *http.Request) {
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.SetEscapeHTML(true)
	e.Encode(c)
}

func encode(w http.ResponseWriter, r *http.Request) {
	e := json.NewEncoder(w)
	e.SetIndent("", "")
	e.SetEscapeHTML(true)
	e.Encode(c)
}

func decode(w http.ResponseWriter, r *http.Request) {
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("got:", c)
	c.Write()
}

var c Config

func sha256Example(msg string) string {
	hashF := sha256.New()
	hashF.Write([]byte(msg))
	hashS := hex.EncodeToString(hashF.Sum(nil))
	return string(hashS)
}

type UserClaims struct {
	jwt.StandardClaims
	SessionId int64
}

var key []byte

func createJWT(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	return t.SignedString(t)
}

func main() {
	c.Read()
	fmt.Println("config:\n", c)
	c.SetDefaults()
	defer c.Write()

	fmt.Println("hash is:", sha256Example("hello"))

	http.HandleFunc("/encodepp", encodepp)
	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)

	err := http.ListenAndServe(c.Port, nil)
	if err != nil {
		panic(err)
	}

}
