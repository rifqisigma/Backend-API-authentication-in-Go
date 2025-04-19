package main

import (
	"api_auth/cmd/config"
	"api_auth/cmd/database"
	"api_auth/cmd/route"
	"api_auth/internal/handler"
	"api_auth/internal/repository"
	"api_auth/internal/usecase"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	database.ConnectDB()

	//google provider config
	config.InitGoogleOAuth()
	config.InitGoogleVerifier()

	//auth
	authRepo := repository.NewAuthRepository(database.DB)
	authUsecase := usecase.NewAuthUsecase(authRepo)
	authHandler := handler.NewAuthHandler(authUsecase)

	r := route.SetupRoute(authHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🚀 Server running on http://localhost:" + port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
