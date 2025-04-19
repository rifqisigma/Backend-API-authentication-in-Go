package utils

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/gomail.v2"
)

func IsValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

func SendEmail(toEmail, token string) {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", os.Getenv("EMAIL_SENDER"))
	mailer.SetHeader("To", toEmail)
	mailer.SetHeader("Subject", "Verify Your Account")
	mailer.SetBody("text/html", fmt.Sprintf(`<a href="http://localhost:8080/gmail/verification?email=%s&token=%s">Klik di sini untuk verifikasi</a>`, toEmail, token))
	dialer := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("EMAIL_SENDER"), os.Getenv("APP_PASSWORD"))

	fmt.Println("Verification Link:")
	fmt.Printf("http://localhost:8080/gmail/verification?email=%s&token=%s\n", toEmail, token)
	if err := dialer.DialAndSend(mailer); err != nil {
		fmt.Println("Error sending email:", err)
	}
}
