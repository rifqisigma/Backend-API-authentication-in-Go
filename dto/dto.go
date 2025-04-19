package dto

import (
	"time"
)

type UserInfo struct {
	ProviderID string `json:"provider_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Picture    string `json:"picture"`
}

type UserUpdate struct {
	ID      string `json:"-"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type UserResponseUpdate struct {
	ID      string `json:"Id"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type UserResponse struct {
	ID                 uint      `json:"id"`
	Email              string    `json:"email"`
	Picture            string    `json:"avatar"`
	RefreshToken       string    `json:"refresh_token"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
	AccessToken        string    `json:"access_token"`
	AccessTokenExpiry  time.Time `json:"acces_token_expiry"`
}

type UserGetNewRefreshToken struct {
	ID           uint   `json:"-"`
	RefreshToken string `json:"refresh_token"`
}

// gmail traditional
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Email    string `json:"email"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

type Register struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Provider string `json:"-"`
	Name     string `json:"name"`
}

type RegisterResponse struct {
	ID       uint
	Email    string
	Provider string
	Verified bool
}
