package utils

import (
	"api_auth/dto"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func ParseGoogleUserInfo(data []byte) (*dto.UserInfo, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	providerID := ""
	if val, ok := raw["sub"]; ok {
		providerID = fmt.Sprint(val)
	} else if val, ok := raw["id"]; ok {
		providerID = fmt.Sprint(val)
	}

	user := &dto.UserInfo{
		ProviderID: providerID,
		Email:      fmt.Sprint(raw["email"]),
		Name:       fmt.Sprint(raw["name"]),
		Picture:    fmt.Sprint(raw["picture"]),
	}

	return user, nil
}

func DetectDevice(r *http.Request) string {
	userAgent := r.UserAgent()

	if strings.Contains(userAgent, "Mobile") {
		return "mobile"
	}
	return "web"
}

func SetAuthCookies(w http.ResponseWriter, resp *dto.UserResponse) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    resp.RefreshToken,
		Expires:  resp.RefreshTokenExpiry,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, //untuk localhost , tahap pengembangan
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    resp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, //untuk localhost , tahap pengembangan
		SameSite: http.SameSiteStrictMode,
	})
}
