package middleware

import (
	"api_auth/utils"
	"context"
	"net/http"
	"strings"
	"time"
)

type key int

const UserContextKey key = 0

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token missing", http.StatusUnauthorized)
			return
		}
		claims, err := utils.ParseJWT(tokenString)
		if err != nil || time.Now().After(claims.ExpiresAt.Time) {
			device := utils.DetectDevice(r)
			if device == "mobile" {
				refreshToken := r.Header.Get("X-Refresh-Token")
				if refreshToken == "" {
					http.Error(w, "Refresh token missing", http.StatusUnauthorized)
					return
				}
				valid, err := utils.ValidateExpiryRefreshToken(claims.UserID, refreshToken)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if !valid {
					http.Error(w, "refresh token invalid or expiry ", http.StatusUnauthorized)
					return
				}
				newAccessToken, err := utils.GenerateJWT(claims.Email, claims.Provider, claims.UserID, claims.Verified)
				if err != nil {
					http.Error(w, "failed get new akses token", http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-New-Access-Token", newAccessToken)

			} else if device == "web" {
				cookie, err := r.Cookie("refresh_token")
				if err != nil {
					http.Error(w, "missing refresh token", http.StatusUnauthorized)
					return
				}

				refreshToken := cookie.Value
				valid, err := utils.ValidateExpiryRefreshToken(claims.UserID, refreshToken)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if !valid {
					http.Error(w, "refresh token invalid or expiry ", http.StatusUnauthorized)
					return
				}
				newAccessToken, err := utils.GenerateJWT(claims.Email, claims.Provider, claims.UserID, claims.Verified)
				if err != nil {
					http.Error(w, "failed get new akses token", http.StatusInternalServerError)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     "access_token",
					Value:    newAccessToken,
					Path:     "/",
					HttpOnly: true,
					Secure:   false, //untuk localhost , tahap pengembangan
					SameSite: http.SameSiteStrictMode,
				})

			}

		}

		if !claims.Verified {
			http.Error(w, "unverified user", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
