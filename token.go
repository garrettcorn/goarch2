package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type customClaims struct {
	jwt.RegisteredClaims
	SID string
}

var key = []byte("my secret key 007 james bond rule the world from my mom's basement")

func createToken(sid string) (string, error) {

	cc := customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("couldn't sign token in createToken %w", err)
	}
	return st, nil
}

func parseToken(st string) (string, error) {
	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return key, nil
	})

	if err != nil {
		return "", fmt.Errorf("couldn't ParseWithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}

	return token.Claims.(*customClaims).SID, nil
}
