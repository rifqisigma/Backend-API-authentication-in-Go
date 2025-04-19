package route

import (
	"api_auth/internal/handler"
	"api_auth/middleware"
	"net/http"

	"github.com/gorilla/mux"
)

func SetupRoute(auth *handler.AuthHandler) *mux.Router {
	r := mux.NewRouter()

	//google login
	r.HandleFunc("/google/login", auth.GoogleLogin).Methods(http.MethodGet)
	r.HandleFunc("/google/callback", auth.GoogleCallback).Methods(http.MethodGet)
	r.HandleFunc("/google/mobile/login", auth.GoogleMobile).Methods(http.MethodPost)

	//gmail login
	r.HandleFunc("/gmail/login", auth.GmailLogin).Methods(http.MethodPost)
	r.HandleFunc("/gmail/register", auth.GmailRegister).Methods(http.MethodPost)
	r.HandleFunc("/gmail/verification", auth.GmailVerificationUser).Methods(http.MethodGet)

	secure := r.PathPrefix("/auth").Subrouter()
	secure.Use(middleware.JWTMiddleware)

	secure.HandleFunc("/refresh-token", auth.GetNewRefreshToken).Methods(http.MethodPost)
	secure.HandleFunc("/logout", auth.Logout).Methods(http.MethodPost)
	secure.HandleFunc("/edit-profile", auth.UpdateAccount).Methods(http.MethodPut)
	secure.HandleFunc("/delete-account", auth.DeleteAccount).Methods(http.MethodDelete)
	return r
}
