package repository

import (
	"api_auth/dto"
	"api_auth/model"
	"api_auth/utils"
	"errors"
	"time"

	"gorm.io/gorm"
)

type AuthRepository interface {
	FirstOrCreateGoogleUser(googleUser *model.User) (*model.User, bool, error)
	UpdateRefreshToken(userID uint, refreshToken string, expiry time.Time) error
	IsRefreshTokenValid(userID uint) (bool, error)
	GetNewRefreshToken(oldToken string, userID uint) (string, error)
	Logout(userID uint) error
	UpdateUser(user *dto.UserUpdate) (*dto.UserResponseUpdate, error)
	DeleteUser(userID uint) error

	//gmail traditional
	Login(input *dto.Login) (*dto.LoginResponse, string, error)
	Register(input *dto.Register) (*dto.RegisterResponse, error)
	VerifiedTrueUser(userID uint) error
}
type authRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &authRepository{db}
}

func (r *authRepository) FirstOrCreateGoogleUser(googleUser *model.User) (*model.User, bool, error) {
	var user model.User
	result := r.db.Where(model.User{Provider: googleUser.Provider, ProviderID: googleUser.ProviderID}).
		Attrs(*googleUser).
		FirstOrCreate(&user)

	if result.Error != nil {
		return nil, false, result.Error
	}

	isNew := result.RowsAffected > 0
	return &user, isNew, nil
}

func (r *authRepository) UpdateRefreshToken(userID uint, refreshToken string, expiry time.Time) error {
	return r.db.Model(&model.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"refresh_token":        refreshToken,
			"refresh_token_expiry": expiry,
		}).Error
}

func (r *authRepository) IsRefreshTokenValid(userID uint) (bool, error) {
	var user model.User
	err := r.db.Select("refresh_token_expiry").Where("id = ?", userID).First(&user).Error
	if err != nil {
		return false, err
	}

	if time.Now().After(user.RefreshTokenExpiry) {
		return false, nil
	}

	return true, nil
}

func (r *authRepository) GetNewRefreshToken(oldToken string, userID uint) (string, error) {
	var refreshToken struct {
		RefreshToken       string
		RefreshTokenExpiry time.Time
	}

	if err := r.db.Select("refresh_token,refresh_token_expiry").Where("id = ? AND refresh_token = ?", userID, oldToken).Table("users").First(&refreshToken).Error; err != nil {
		return "", err
	}

	valid, err := utils.ValidateToken(refreshToken.RefreshToken, oldToken)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", errors.New("invalid token")
	}

	if time.Now().After(refreshToken.RefreshTokenExpiry) {
		return "", errors.New("token expired, please login")
	}
	newToken, refreshHash := utils.GenerateRefreshToken()

	refreshToken.RefreshToken = refreshHash
	refreshToken.RefreshTokenExpiry = time.Now().Add(30 * 24 * time.Hour)
	if err := r.db.Where("id = ?", userID).Updates(refreshToken).Error; err != nil {
		return "", err
	}

	return newToken, nil

}

func (r *authRepository) Logout(userID uint) error {
	if err := r.db.Where("id = ?", userID).Update("refresh_token", "").Error; err != nil {
		return err
	}

	return nil
}

func (r *authRepository) UpdateUser(user *dto.UserUpdate) (*dto.UserResponseUpdate, error) {
	updated := model.User{
		Name:   user.Name,
		Avatar: user.Picture,
	}

	if err := r.db.Model(&model.User{}).Select("id,avatar,email,name").Where("id = ?", user.ID).Updates(&updated).Error; err != nil {
		return nil, err
	}

	response := dto.UserResponseUpdate{
		ID:      user.ID,
		Picture: updated.Avatar,
		Name:    updated.Name,
	}
	return &response, nil
}

func (r *authRepository) DeleteUser(userID uint) error {
	if err := r.db.Model(&model.User{}).Where("id = ?", userID).Delete(&model.User{}).Error; err != nil {
		return err
	}

	return nil
}

func (r *authRepository) Register(input *dto.Register) (*dto.RegisterResponse, error) {
	user := model.User{
		Email:    input.Email,
		Password: input.Password,
		Name:     input.Name,
		Provider: "gmail",
	}
	if err := r.db.Create(&user).Error; err != nil {
		return nil, err
	}

	response := dto.RegisterResponse{
		ID:       user.ID,
		Email:    user.Email,
		Verified: user.IsVerified,
		Provider: user.Provider,
	}
	return &response, nil
}

func (r *authRepository) Login(input *dto.Login) (*dto.LoginResponse, string, error) {
	var user model.User
	err := r.db.Select("email,provider,name").Where("email = ? AND verified = ?", input.Email, true).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, "", errors.New("email unverified")
		}
	}

	response := dto.LoginResponse{
		Email:    user.Email,
		Provider: user.Provider,
		Name:     user.Name,
	}
	return &response, user.Password, nil
}

func (r *authRepository) VerifiedTrueUser(userID uint) error {
	err := r.db.Model(&model.User{}).Where("id = ?", userID).Update("is_verified", true).Error
	if err != nil {
		return err
	}

	return nil
}
