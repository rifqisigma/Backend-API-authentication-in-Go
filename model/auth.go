package model

import (
	"time"
)

type User struct {
	ID                 uint   `gorm:"primaryKey"`
	Email              string `gorm:"type:varchar(191);unique"`
	Password           string
	Provider           string `gorm:"type:varchar(50)"`
	ProviderID         string `gorm:"type:varchar(191);index"`
	Name               string `gorm:"type:varchar(255)"`
	Avatar             string `gorm:"type:varchar(255)"`
	IsVerified         bool   `gorm:"default:false"`
	RefreshToken       string `gorm:"type:varchar(255)"`
	RefreshTokenExpiry time.Time
	CreatedAt          time.Time
}
