package main

import (
	"api_auth/cmd/database"
	"api_auth/model"
	"log"
)

func main() {

	database.ConnectDB()

	if database.DB == nil {
		log.Fatal("❌ Database belum diinisialisasi")
	}

	err := database.DB.AutoMigrate(&model.User{})
	if err != nil {
		log.Fatalf("gagal migrasi boy %v", err)
	}

	log.Println("berhasil migrasi")

}
