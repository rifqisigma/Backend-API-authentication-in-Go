# 🛡️ Golang REST API Authentication

Sebuah proyek REST API authentication menggunakan **Golang** dengan dukungan:
- Login via **Google OAuth2** (web & mobile) mobile belum pernah testing karena tak ada testing frontend
- Login via **Gmail (tradisional)**
- Middleware **Bearer Token** (JWT)
- Validasi email via link verifikasi (untuk Gmail)
- Perbedaan handling login antara Web & Mobile (terutama OAuth2)

---

## 🚀 Features

✅ Login/Register dengan Google (Web & Mobile)  
✅ Login/Register dengan Gmail + Password  
✅ Kirim link verifikasi email (Gmail)  
✅ Middleware autentikasi Bearer Token  
✅ Refresh token + auto-extend access token  
✅ Pada Mobile validasi token dengan `github.com/coreos/go-oidc`  
✅ Clean code dengan Clean Architecture