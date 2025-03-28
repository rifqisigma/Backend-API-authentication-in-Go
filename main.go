package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Struct User untuk GORM
type User struct {
	ID         uint   `gorm:"primaryKey"`
	Email      string `gorm:"type:varchar(191);unique"`
	Password   string `gorm:"type:varchar(255)"`
	Provider   string `gorm:"type:varchar(50)"`
	ProviderID string `gorm:"type:varchar(191);index"`
	Name       string `gorm:"type:varchar(255)"`
	Avatar     string `gorm:"type:varchar(255)"`
	IsVerified bool   `gorm:"default:false"`
	CreatedAt  time.Time
}

// JWT Secret
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// OAuth Configs
var googleOAuthConfig *oauth2.Config
var githubOAuthConfig *oauth2.Config

// Database Connection
var db *gorm.DB

func init() {
	// Load .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect to MySQL with GORM
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}

	// Migrasi otomatis
	db.AutoMigrate(&User{})

	// Google OAuth Config
	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// GitHub OAuth Config
	githubOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"),
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
}

// Generate JWT Token
func generateJWT(email string, isVerified bool) (string, error) {
	claims := jwt.MapClaims{
		"email":      email,
		"isVerified": isVerified,
		"exp":        time.Now().Add(time.Hour * 24).Unix(), // Expire in 24 hours
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Google Login Handler
func googleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL("randomstate")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Google Callback Handler
func googleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := googleOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "OAuth exchange failed", http.StatusBadRequest)
		return
	}

	// Get user info
	client := googleOAuthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]string
	json.NewDecoder(resp.Body).Decode(&userInfo)

	// Simpan user ke database menggunakan GORM
	user := User{}
	db.Where(User{Email: userInfo["email"], Provider: "google"}).
		Assign(User{Name: userInfo["name"], Avatar: userInfo["picture"], ProviderID: userInfo["id"], IsVerified: true}).
		FirstOrCreate(&user)

	// Generate JWT
	tokenString, _ := generateJWT(userInfo["email"], user.IsVerified)

	// Return JWT
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      tokenString,
		"isVerified": user.IsVerified,
	})
}

// GitHub Login Handler
func githubLogin(w http.ResponseWriter, r *http.Request) {
	url := githubOAuthConfig.AuthCodeURL("randomstate")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GitHub Callback Handler
func githubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := githubOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "OAuth exchange failed", http.StatusBadRequest)
		return
	}

	// Get user info
	client := githubOAuthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)

	// Simpan user ke database menggunakan GORM
	email := fmt.Sprintf("%v", userInfo["email"])
	user := User{}
	db.Where(User{Email: email, Provider: "github"}).
		Assign(User{Name: fmt.Sprintf("%v", userInfo["name"]), Avatar: fmt.Sprintf("%v", userInfo["avatar_url"]), ProviderID: fmt.Sprintf("%v", userInfo["id"]), IsVerified: true}).
		FirstOrCreate(&user)

	// Generate JWT
	tokenString, _ := generateJWT(email, user.IsVerified)

	// Return JWT
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      tokenString,
		"isVerified": user.IsVerified,
	})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/auth/google/login", googleLogin).Methods(http.MethodGet)
	r.HandleFunc("/auth/google/callback", googleCallback).Methods(http.MethodGet)
	r.HandleFunc("/auth/github/login", githubLogin).Methods(http.MethodGet)
	r.HandleFunc("/auth/github/callback", githubCallback).Methods(http.MethodGet)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
