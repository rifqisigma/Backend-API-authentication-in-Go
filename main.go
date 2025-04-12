package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// ===================== DB ======================

type User struct {
	ID                 uint      `gorm:"primaryKey"`
	Email              string    `gorm:"type:varchar(191);unique"`
	Provider           string    `gorm:"type:varchar(50)"`
	ProviderID         string    `gorm:"type:varchar(191);index"`
	Name               string    `gorm:"type:varchar(255)"`
	Avatar             string    `gorm:"type:varchar(255)"`
	IsVerified         bool      `gorm:"default:false"`
	RefreshToken       string    `gorm:"type:varchar(255)"`
	RefreshTokenExpiry time.Time `gorm:"index"`
	CreatedAt          time.Time
}

var db *gorm.DB

// ===================== OAuth2 ======================

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
	Endpoint:     google.Endpoint,
}

var jwtSecret = []byte("SECRET_KEY") // ganti dengan env secret

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Tukar kode dengan token
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Buat client dengan token yang didapat
	client := googleOauthConfig.Client(context.Background(), token)

	// Ambil data user dari Google
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Decode response menjadi userInfo struct
	var userInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	// Buat atau ambil user berdasarkan provider (google) dan provider_id (userInfo.ID)
	var refreshToken, refreshHash string
	user := User{
		Provider:   "google",
		ProviderID: userInfo.ID,
		Email:      userInfo.Email,
		Name:       userInfo.Name,
		Avatar:     userInfo.Picture,
		IsVerified: true,
	}

	// `FirstOrCreate` akan mencari user berdasarkan provider dan provider_id, jika tidak ada maka akan dibuat
	result := db.Where(User{Provider: "google", ProviderID: userInfo.ID}).FirstOrCreate(&user)

	if result.Error != nil {
		http.Error(w, "Failed to find or create user: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Generate refresh token dan update user dengan refresh token baru
	refreshToken, refreshHash = generateRefreshToken()
	user.RefreshToken = refreshHash
	user.RefreshTokenExpiry = time.Now().Add(30 * 24 * time.Hour)

	// Simpan perubahan user ke database
	if result.RowsAffected > 0 {
		db.Save(&user) // Menyimpan jika user baru atau ada perubahan pada user yang ada
	}

	// Generate JWT token untuk user
	accessToken, err := generateJWT(user)
	if err != nil {
		http.Error(w, "Failed to create JWT", http.StatusInternalServerError)
		return
	}

	// Response dengan access token dan refresh token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"expires_in":    900, // Misalnya token berlaku selama 15 menit
		"refresh_token": refreshToken,
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Ambil claims dari context (yang di-set di middleware)
	claims, ok := r.Context().Value(UserContextKey).(*JWTclaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Ambil user dari database
	var user User
	if err := db.First(&user, claims.UserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Kosongkan refresh token dan expiry
	user.RefreshToken = ""
	user.RefreshTokenExpiry = time.Time{}
	db.Save(&user)

	// Respon
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string `json:"email"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	valid, err := ValidateRefreshToken(user, req.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if !valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Generate new access token
	accessToken, err := generateJWT(user)
	if err != nil {
		http.Error(w, "Failed to create JWT", http.StatusInternalServerError)
		return
	}

	// Optional: Rotasi refresh token
	newRaw, newHashed := generateRefreshToken()
	user.RefreshToken = newHashed
	user.RefreshTokenExpiry = time.Now().Add(30 * 24 * time.Hour)
	db.Save(&user)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"expires_in":    900,
		"refresh_token": newRaw,
	})
}

// ===================== Helpers ======================

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

type JWTclaims struct {
	UserID             uint      `json:"user_id"`
	Email              string    `json:"email"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
	jwt.RegisteredClaims
}

func generateJWT(user User) (string, error) {
	claims := JWTclaims{
		UserID:             user.ID,
		Email:              user.Email,
		RefreshTokenExpiry: user.RefreshTokenExpiry,
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

func generateRefreshToken() (string, string) {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	raw := base64.URLEncoding.EncodeToString(tokenBytes)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	return raw, string(hashed)
}

func ValidateRefreshToken(user User, rawToken string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(rawToken)); err != nil {
		return false, errors.New("invalid refresh token")
	}
	if time.Now().After(user.RefreshTokenExpiry) {
		return false, errors.New("refresh token expired")
	}
	return true, nil
}

// Fungsi untuk mengecek apakah refresh token masih valid
func isRefreshTokenValid(userID uint) (bool, error) {
	// Mengambil user dari database berdasarkan user ID
	var user User
	err := db.Where("provider_id = ?", userID).First(&user).Error
	if err != nil {
		// Jika user tidak ditemukan
		return false, err
	}

	// Mengecek apakah refresh token sudah expired
	if time.Now().After(user.RefreshTokenExpiry) {
		// Jika refresh token expired
		return false, nil
	}

	// Jika refresh token masih valid
	return true, nil
}

// middeware
type key int

const UserContextKey key = 0

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mengambil token dari header Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Mengekstrak token Bearer
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token missing", http.StatusUnauthorized)
			return
		}

		// Validasi JWT
		claims, err := ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Cek apakah token sudah expired (akses token)
		if claims.RefreshTokenExpiry.Before(time.Now()) {
			// Token kedaluwarsa, cek refresh token di database
			isValid, err := isRefreshTokenValid(claims.UserID)
			if err != nil {
				http.Error(w, "Failed to check refresh token", http.StatusInternalServerError)
				return
			}

			if !isValid {
				http.Error(w, "Refresh token expired, please log in again", http.StatusUnauthorized)
				return
			}

			// Jika refresh token valid, buatkan akses token baru
			var user User
			err = db.Where("provider_id = ?", claims.UserID).First(&user).Error
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			accessToken, err := generateJWT(user)
			if err != nil {
				http.Error(w, "Failed to create new access token", http.StatusInternalServerError)
				return
			}

			// Kirim akses token baru ke client
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": accessToken,
			})
			return
		}

		// Menambahkan klaim ke context untuk digunakan di handler berikutnya

		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		// Panggil handler berikutnya
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	dsn := "link db"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&User{})

	r := mux.NewRouter()
	r.HandleFunc("/auth/google/login", googleLoginHandler)
	r.HandleFunc("/auth/google/callback", googleCallbackHandler)

	protectRoute := r.PathPrefix("/protect").Subrouter()
	protectRoute.Use(JWTMiddleware)

	protectRoute.HandleFunc("/refresh-token", RefreshTokenHandler)
	protectRoute.HandleFunc("/logout", LogoutHandler)

	log.Println("Running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
