package utils

import (
	"api_auth/cmd/database"
	"api_auth/model"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// csrf
func GenerateState() string {
	b := make([]byte, 16) // 128-bit
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func ValidateState(state string) bool {
	if len(state) != 22 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(state)
	return err == nil
}

// hash pw
func HashPassword(password string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

func ValidateToken(hashedToken, rawToken string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(rawToken)); err != nil {
		return false, errors.New("invalid refresh token")
	}
	return true, nil
}

// refresh token
func GenerateRefreshToken() (string, string) {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	raw := base64.URLEncoding.EncodeToString(tokenBytes)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	return raw, string(hashed)
}

func ValidateExpiryRefreshToken(userID uint, refreshToken string) (bool, error) {
	var user model.User
	err := database.DB.Model(&model.User{}).Select("refresh_token_expiry").Where("id = ? AND refresh_token = ?", userID, refreshToken).First(&user).Error
	if err != nil {
		return false, err
	}

	if time.Now().After(user.RefreshTokenExpiry) {
		return false, nil
	}

	return true, nil
}
