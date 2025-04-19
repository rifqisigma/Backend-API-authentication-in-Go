package config

import (
	"context"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var GoogleOAuthConfig *oauth2.Config

// mobile
var GoogleVerifier *oidc.IDTokenVerifier
var GoogleMobileOauth = os.Getenv("GOOGLE_CLIENT_ID_MOBILE")

func InitGoogleOAuth() {
	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID_WEB"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET_WEB"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL_WEB"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

}

// Init di awal aplikasi kamu
func InitGoogleVerifier() error {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return err
	}
	GoogleVerifier = provider.Verifier(&oidc.Config{ClientID: GoogleMobileOauth})
	return nil
}
