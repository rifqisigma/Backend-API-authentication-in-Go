package handler

import (
	"api_auth/cmd/config"
	"api_auth/dto"
	"api_auth/internal/usecase"
	"api_auth/middleware"
	"api_auth/utils"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type AuthHandler struct {
	authUsecase usecase.AuthUsecase
}

func NewAuthHandler(authUsecase usecase.AuthUsecase) *AuthHandler {
	return &AuthHandler{authUsecase}
}

func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := utils.GenerateState()
	url := h.authUsecase.GoogleLoginURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "No state provided", http.StatusBadRequest)
		return
	}
	if valid := utils.ValidateState(state); !valid {
		http.Error(w, "state not valid", http.StatusBadRequest)
		return
	}

	token, err := config.GoogleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := config.GoogleOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// if resp.StatusCode != http.StatusOK {
	// 	errorBody, _ := io.ReadAll(resp.Body)
	// 	return fmt.Errorf("Google API error: %s", string(errorBody))
	// }

	body, _ := io.ReadAll(resp.Body)

	userInfo, err := utils.ParseGoogleUserInfo(body)
	if err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	response, err := h.authUsecase.CreateOrUpdateGoogleUser(userInfo)
	if err != nil {
		http.Error(w, "Usecase error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//untuk kuki saya belum pernah testing langsung karena endpoint callback mengandung outh2config dari /login yg tidak bisa saya dapatkan dengan ketik manual
	utils.SetAuthCookies(w, response)
	utils.WriteJSON(w, http.StatusCreated, response)
}

func (h *AuthHandler) GoogleMobile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		http.Error(w, `{"error":"Invalid id_token"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	idToken, err := config.GoogleVerifier.Verify(ctx, req.IDToken)
	if err != nil {
		http.Error(w, `{"error":"Invalid or expired id_token"}`, http.StatusUnauthorized)
		return
	}

	var claims map[string]interface{}
	_ = idToken.Claims(&claims)
	jsonData, _ := json.Marshal(claims)

	userInfo, err := utils.ParseGoogleUserInfo(jsonData)
	if err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	resp, err := h.authUsecase.CreateOrUpdateGoogleUser(userInfo)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, resp)
}

func (h *AuthHandler) GetNewRefreshToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*utils.JWTclaims)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	var input dto.UserGetNewRefreshToken
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}

	input.ID = claims.UserID
	newRefreshToken, err := h.authUsecase.GetNewRefreshToken(input.RefreshToken, input.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"new refresh token": newRefreshToken,
	})

}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*utils.JWTclaims)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, "invalid access token")
		return
	}
	if err := h.authUsecase.Logout(claims.UserID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "succed delete account",
	})
}

func (h *AuthHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*utils.JWTclaims)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	var input dto.UserUpdate
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}

	input.ID = claims.ID
	response, err := h.authUsecase.UpdateUser(&input)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*utils.JWTclaims)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	if err := h.authUsecase.DeleteUser(claims.UserID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "succed delete account",
	})
}

func (h *AuthHandler) GmailLogin(w http.ResponseWriter, r *http.Request) {
	var input dto.Login

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}

	response, err := h.authUsecase.Login(&input)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) GmailRegister(w http.ResponseWriter, r *http.Request) {
	var input dto.Register

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}

	err := h.authUsecase.Register(&input)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "succedd send link verification ",
	})
}

func (h *AuthHandler) GmailVerificationUser(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		utils.WriteError(w, http.StatusBadRequest, "No token provided")
		return
	}

	claims, err := utils.ParseJWT(token)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "invalid claims token")
		return
	}

	if err := h.authUsecase.VerifiedTrueUser(claims.UserID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "succedd verification user",
	})
}
