package usecase

import (
	"api_auth/cmd/config"
	"api_auth/dto"
	"api_auth/internal/repository"
	"api_auth/model"
	"api_auth/utils"
	"errors"
	"time"
)

type AuthUsecase interface {

	//google auth
	GoogleLoginURL(state string) string
	CreateOrUpdateGoogleUser(userInfo *dto.UserInfo) (*dto.UserResponse, error)
	GetNewRefreshToken(oldToken string, userID uint) (string, error)
	// GoogleMobileLogin()

	Logout(userID uint) error
	UpdateUser(user *dto.UserUpdate) (*dto.UserResponseUpdate, error)
	DeleteUser(userID uint) error

	//gmail auth
	Login(input *dto.Login) (*dto.LoginResponse, error)
	Register(input *dto.Register) error
	VerifiedTrueUser(userID uint) error
}

type authUsecase struct {
	authRepo repository.AuthRepository
}

func NewAuthUsecase(authRepo repository.AuthRepository) AuthUsecase {
	return &authUsecase{authRepo}
}

// google auth
func (u *authUsecase) GoogleLoginURL(state string) string {
	return config.GoogleOAuthConfig.AuthCodeURL(state)
}

func (u *authUsecase) CreateOrUpdateGoogleUser(userInfo *dto.UserInfo) (*dto.UserResponse, error) {
	refreshToken, refreshHash := utils.GenerateRefreshToken()
	expiry := time.Now().Add(30 * 24 * time.Hour)
	newUser := &model.User{
		Provider:           "google",
		ProviderID:         userInfo.ProviderID,
		Email:              userInfo.Email,
		Name:               userInfo.Name,
		Avatar:             userInfo.Picture,
		IsVerified:         true,
		RefreshToken:       refreshHash,
		RefreshTokenExpiry: expiry,
	}

	user, isNew, err := u.authRepo.FirstOrCreateGoogleUser(newUser)
	if err != nil {
		return nil, err
	}

	if !isNew {
		err = u.authRepo.UpdateRefreshToken(user.ID, refreshHash, expiry)
		if err != nil {
			return nil, err
		}
	}

	accessToken, err := utils.GenerateJWT(newUser.Email, newUser.Provider, newUser.ID, newUser.IsVerified)
	if err != nil {
		return nil, err
	}

	response := dto.UserResponse{
		ID:                 user.ID,
		Email:              user.Email,
		Picture:            user.Avatar,
		RefreshToken:       refreshToken,
		RefreshTokenExpiry: user.RefreshTokenExpiry,
		AccessToken:        accessToken,
	}
	return &response, nil
}

// query
func (u *authUsecase) GetNewRefreshToken(oldToken string, userID uint) (string, error) {
	valid, err := u.authRepo.IsRefreshTokenValid(userID)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", errors.New("expired token, please login")
	}
	return u.authRepo.GetNewRefreshToken(oldToken, userID)
}

func (u *authUsecase) Logout(userID uint) error {
	return u.authRepo.Logout(userID)
}

func (u *authUsecase) UpdateUser(user *dto.UserUpdate) (*dto.UserResponseUpdate, error) {
	return u.authRepo.UpdateUser(user)
}

func (u *authUsecase) DeleteUser(userID uint) error {
	return u.authRepo.DeleteUser(userID)
}

// gmail auth
func (u *authUsecase) Login(input *dto.Login) (*dto.LoginResponse, error) {
	valid := utils.IsValidEmail(input.Email)
	if !valid {
		return nil, errors.New("invalid email")
	}

	response, hashed, err := u.authRepo.Login(input)
	if err != nil {
		return nil, err
	}

	validpw, err := utils.ValidateToken(hashed, input.Password)
	if err != nil {
		return nil, err
	}
	if !validpw {
		return nil, err
	}

	return response, nil
}

func (u *authUsecase) Register(input *dto.Register) error {
	if valid := utils.IsValidEmail(input.Email); !valid {
		return errors.New("invalid email")
	}

	hashed := utils.HashPassword(input.Password)

	input.Password = hashed
	user, err := u.authRepo.Register(input)
	if err != nil {
		return err
	}

	token, err := utils.GenerateJWT(user.Email, user.Provider, user.ID, user.Verified)
	if err != nil {
		return err
	}

	utils.SendEmail(input.Email, token)
	return nil
}

func (u *authUsecase) VerifiedTrueUser(userID uint) error {
	return u.authRepo.VerifiedTrueUser(userID)
}
