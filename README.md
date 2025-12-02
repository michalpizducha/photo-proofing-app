# 📸 Julia Berlik Foto - System Proofingu Zdjęć

> Profesjonalny system do wyboru i dostarczania zdjęć fotograficznych z eleganckimi mailami i automatycznym pakowaniem.

![Version](https://img.shields.io/badge/version-4.0.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## ✨ Nowe Funkcje (v4.0)

### 🎯 Dla Klientów
- **Pełnoekranowa galeria** z nawigacją klawiaturą i gestami
- **Progress bar** pokazujący postęp wyboru zdjęć
- **Strona FAQ** z odpowiedziami na częste pytania
- **Moje Sesje** - przeglądanie historii własnych sesji
- **Responsywna nawigacja** działająca na wszystkich urządzeniach
- **Licznik zdjęć** w lightboxie
- **Animacje** i mikrointerakcje

### 💼 Dla Fotografa
- **Drag & Drop upload** zdjęć z podglądem
- **Wizualny progress bar** podczas uploadu
- **Automatyczne pakowanie ZIP** z pełną rozdzielczością
- **Eleganckie maile HTML** z brandingiem
- **Ulepszona nawigacja** w panelu admina
- **Kopiowanie nazw plików** jednym kliknięciem

### 🎨 Design
- Profesjonalny design system
- Dark mode (automatyczny)
- Płynne animacje i przejścia
- Typografia: Cinzel + Raleway
- Paleta kolorów: Złoty akcent (#c5a059)
- Masonry grid dla zdjęć

---

## 🚀 Szybki Start

### Wymagania
- Node.js >= 16.0.0
- PostgreSQL
- Google Cloud Storage
- Konto Brevo (SendInBlue) do mailingu

### Instalacja

```bash
# Sklonuj repozytorium
git clone https://github.com/michalpizducha/photo-proofing-app.git
cd photo-proofing-app

# Zainstaluj zależności
npm install

# Skonfiguruj zmienne środowiskowe
cp .env.example .env
# Edytuj .env i uzupełnij dane

# Uruchom aplikację
npm start
```

### Konfiguracja `.env`

```env
# Database
DATABASE_URL=postgresql://user:password@host:5432/database

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this

# Google Cloud Storage
GCS_PROJECT_ID=your-project-id
GCS_BUCKET_NAME=your-bucket-name
GOOGLE_CREDENTIALS_BASE64=base64-encoded-service-account-key

# Email (Brevo)
BREVO_API_KEY=your-brevo-api-key
EMAIL_USER=julia@example.com

# App
APP_URL=https://your-app.com
NODE_ENV=production
PORT=3000
```

---

## 📖 Dokumentacja

### Architektura

```
┌─────────────────────────────────────────────┐
│           Frontend (Vanilla JS)             │
│  - Single Page Application                  │
│  - Router system                            │
│  - State management                         │
└─────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────┐
│         Backend (Express.js)                │
│  - RESTful API                              │
│  - JWT Authentication                       │
│  - Rate Limiting                            │
└─────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────┐
│           Services                          │
│  ├─ PostgreSQL (Database)                   │
│  ├─ Google Cloud Storage (Files)            │
│  ├─ Brevo (Email)                           │
│  └─ Sharp (Image Processing)                │
└─────────────────────────────────────────────┘
```

### API Endpoints

#### Autoryzacja
```
POST   /api/auth/login       - Logowanie fotografa
POST   /api/auth/logout      - Wylogowanie
GET    /api/auth/check       - Sprawdzenie sesji
```

#### Albumy (Wymagana autoryzacja)
```
GET    /api/admin/albums           - Lista albumów
GET    /api/admin/albums/:id/files - Nazwy plików
POST   /api/albums                 - Nowy album
DELETE /api/albums/:id             - Usuń album
```

#### Upload i Media
```
POST   /api/upload           - Upload zdjęć (batch)
POST   /api/auto-deliver     - Pakowanie ZIP
```

#### Publiczne
```
GET    /api/gallery/:token   - Galeria klienta
POST   /api/select           - Zapisz wybór
POST   /api/sessions/lookup  - Wyszukaj sesje
```

#### Email
```
POST   /api/send-link        - Mail z linkiem do galerii
POST   /api/send-delivery    - Mail z paczką ZIP
```

---

## 🎨 Frontend Features

### Router System
Aplikacja używa custom routera do nawigacji między widokami:
- `/` - Strona główna (O mnie)
- `/#/about` - O fotografce
- `/#/faq` - FAQ
- `/#/my-sessions` - Moje sesje
- `/#/login` - Panel fotografa
- `/gallery/:token` - Galeria klienta

### Keyboard Shortcuts (Lightbox)
- `←` / `A` - Poprzednie zdjęcie
- `→` / `D` - Następne zdjęcie
- `Space` - Wybierz/odznacz zdjęcie
- `F` - Pełny ekran
- `Esc` - Zamknij lightbox

### Touch Gestures (Mobile)
- Swipe lewo/prawo - Nawigacja między zdjęciami
- Tap na zdjęciu - Otwórz lightbox
- Tap na serce - Wybierz zdjęcie

---

## 🔐 Bezpieczeństwo

### Implementowane zabezpieczenia:
- ✅ JWT z httpOnly cookies
- ✅ Helmet.js (CSP, XSS protection)
- ✅ Rate limiting (100 req/15min)
- ✅ CORS configuration
- ✅ SQL injection protection (parametryzowane zapytania)
- ✅ Bcrypt dla haseł
- ✅ Secure cookies w produkcji
- ✅ Znak wodny na proof images
- ✅ Disabled right-click na obrazach

### Rekomendacje dodatkowe:
- [ ] Implementacja CSRF tokens
- [ ] 2FA dla fotografa
- [ ] Backup bazy danych
- [ ] CDN dla statycznych plików
- [ ] Monitoring i logi

---

## 📦 Deploy na Render

### 1. Przygotowanie

**Dodaj do `package.json`:**
```json
{
  "scripts": {
    "start": "node server.js",
    "build": "echo 'No build needed'"
  },
  "engines": {
    "node": ">=16.0.0"
  }
}
```

### 2. Render Dashboard

1. Stwórz **Web Service**
2. Połącz z GitHub repo
3. Ustawienia:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment**: Node

### 3. Zmienne środowiskowe

Dodaj w Render → Environment:
```
DATABASE_URL=...
JWT_SECRET=...
GCS_PROJECT_ID=...
GCS_BUCKET_NAME=...
GOOGLE_CREDENTIALS_BASE64=...
BREVO_API_KEY=...
EMAIL_USER=...
APP_URL=https://your-app.onrender.com
NODE_ENV=production
```

### 4. PostgreSQL na Render

1. Stwórz **PostgreSQL Database**
2. Skopiuj **Internal Database URL**
3. Wklej jako `DATABASE_URL`

### 5. Google Cloud Storage

```bash
# Zakoduj service account key
cat service-account-key.json | base64 > key.txt
# Skopiuj zawartość key.txt do GOOGLE_CREDENTIALS_BASE64
```

### 6. Deploy

```bash
git add .
git commit -m "Ready for production"
git push origin main
```

Render automatycznie zdeployuje aplikację.

---

## 🛠️ Rozbudowa

### Dodanie kolumny client_email do albums

```sql
ALTER TABLE albums ADD COLUMN client_email VARCHAR(255);
```

Zmień w `server.js` endpoint `/sessions/lookup`:
```javascript
WHERE a.client_email = $1
```

### Dodanie limitu wyboru zdjęć

W `public/index.html`:
```javascript
state: { 
    MAX_SELECTION: 50, // Ustaw limit
    // ...
}
```

### Custom branding

W `public/style.css`:
```css
:root {
    --color-accent: #YOUR_COLOR;
    --font-heading: 'YourFont', serif;
}
```

---

## 🐛 Troubleshooting

### Problem: "GCS upload failed"
**Rozwiązanie:** Sprawdź uprawnienia bucket (Storage Object Creator)

### Problem: "Mail nie wysyła się"
**Rozwiązanie:** Zweryfikuj klucz API Brevo i email sender

### Problem: "Database connection timeout"
**Rozwiązanie:** Sprawdź SSL config w Render PostgreSQL

### Problem: "Images not loading"
**Rozwiązanie:** Ustaw bucket jako public lub signed URLs

---

## 📝 Changelog

### v4.0.0 (2025-12-02)
- ✨ Dodano drag & drop upload
- ✨ Dodano progress bar
- ✨ Dodano stronę FAQ
- ✨ Dodano "Moje Sesje"
- ✨ Dodano fullscreen lightbox
- ✨ Eleganckie maile HTML
- 🎨 Przeprojektowanie UI/UX
- 🎨 Responsywna nawigacja
- 🐛 Poprawki wydajności

### v3.1.0
- ✨ Automatyczne pakowanie ZIP
- ✨ Dual upload (proof + full)
- 🎨 Nowy design system

### v3.0.0
- 🚀 Migracja na GCS
- ✨ System proofingu
- 🔐 JWT authentication

---

## 📄 Licencja

MIT © 2025 Julia Berlik Foto

---

## 👤 Autor

**Michal Pizducha**
- GitHub: [@michalpizducha](https://github.com/michalpizducha)

---

## 🙏 Podziękowania

- [Sharp](https://sharp.pixelplumbing.com/) - Image processing
- [Google Cloud](https://cloud.google.com/) - Storage
- [Brevo](https://www.brevo.com/) - Email service
- [Render](https://render.com/) - Hosting

---

**Made with ❤️ for photographers**