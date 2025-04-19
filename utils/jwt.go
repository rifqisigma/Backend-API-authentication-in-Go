package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTclaims struct {
	UserID   uint   `json:"user_id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Provider string `json:"provider"`
	jwt.RegisteredClaims
}

var jwtSecret = []byte("SECRET_KEY")

func GenerateJWT(email, provider string, id uint, verified bool) (string, error) {
	claims := JWTclaims{
		UserID:   id,
		Email:    email,
		Verified: verified,
		Provider: provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenstring string) (*JWTclaims, error) {
	token, err := jwt.ParseWithClaims(tokenstring, &JWTclaims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTclaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
