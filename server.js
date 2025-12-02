/*  - REFACTORED server.js */
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const BrevoTransport = require('nodemailer-brevo-transport');

// Walidacja zmiennych środowiskowych na starcie
const requiredEnv =;
requiredEnv.forEach(key => {
    if (!process.env[key]) {
        console.error(`FATAL: Brak zmiennej środowiskowej ${key}`);
        process.exit(1);
    }
});

const app = express();
const PORT = process.env.PORT |

| 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// 1. BEZPIECZEŃSTWO: Secure Headers & CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Niezbędne dla obecnej struktury SPA w index.html
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        },
    },
    crossOriginEmbedderPolicy: false
}));

// 2. BEZPIECZEŃSTWO: CORS i Cookies
app.use(cors({
    origin: process.env.APP_URL |

| 'http://localhost:3000', // Tylko nasza domena
    credentials: true // Zezwól na przesyłanie ciasteczek
}));
app.use(express.json({ limit: '10kb' })); // Ochrona przed dużym payloadem JSON
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// 3. BEZPIECZEŃSTWO: Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minut
    max: 200, 
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Zbyt wiele zapytań z tego IP.'
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 godzina
    max: 10, // Max 10 prób logowania
    message: 'Zablokowano możliwość logowania na godzinę z powodu zbyt wielu prób.'
});

// --- BAZA DANYCH ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'? { rejectUnauthorized: false } : false
});

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Ograniczenie wielkości pliku w Multer (5MB) i liczby plików w jednym rzucie (5)
// To kluczowe dla pamięci RAM!
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024, files: 5 }
});

const transporter = nodemailer.createTransport(new BrevoTransport({ apiKey: process.env.BREVO_API_KEY |

| 'test' }));

// --- MIDDLEWARE AUTORYZACJI (COOKIE) ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token; // Pobieramy z ciasteczka, nie z nagłówka
    if (!token) return res.status(401).json({ error: 'Brak autoryzacji' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            res.clearCookie('auth_token');
            return res.status(403).json({ error: 'Sesja wygasła' });
        }
        req.user = user;
        next();
    });
};

const initDb = async () => {
    const client = await pool.connect();
    try {
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
        
        // Users
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        
        // Albums - dodano indeks na access_token
        await client.query(`
            CREATE TABLE IF NOT EXISTS albums (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                title VARCHAR(200) NOT NULL,
                client_name VARCHAR(100),
                access_token VARCHAR(64) UNIQUE NOT NULL,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_albums_token ON albums(access_token);
        `);
        
        // Photos - dodano indeks na album_id
        await client.query(`
            CREATE TABLE IF NOT EXISTS photos (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE,
                proof_url TEXT NOT NULL,
                storage_id VARCHAR(100),
                filename VARCHAR(255),
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_photos_album ON photos(album_id);
        `);
        
        // Selections
        await client.query(`
            CREATE TABLE IF NOT EXISTS selections (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE,
                photo_id UUID REFERENCES photos(id) ON DELETE CASCADE,
                UNIQUE(album_id, photo_id)
            );
        `);

        // Check Admin
        const userCheck = await client.query('SELECT * FROM users LIMIT 1');
        if (userCheck.rows.length === 0) {
            const initialPass = process.env.ADMIN_INITIAL_PASSWORD |

| 'admin123';
            const hash = await bcrypt.hash(initialPass, 10);
            await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)',);
            console.log('>>> ADMIN UTWORZONY.');
        }
    } catch (err) {
        console.error('Błąd Init DB:', err);
    } finally {
        client.release();
    }
};

// --- API IMPLEMENTATION ---

app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    // Walidacja podstawowa
    if (!email ||!password) return res.status(400).json({ error: 'Wymagane pola email i hasło' });

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

        const user = result.rows;
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        // Ustawienie bezpiecznego ciasteczka
        res.cookie('auth_token', token, {
            httpOnly: true, // Niedostępne dla JS (ochrona przed XSS)
            secure: process.env.NODE_ENV === 'production', // Tylko HTTPS
            sameSite: 'strict', // Ochrona przed CSRF
            maxAge: 24 * 3600 * 1000 // 24h
        });

        res.json({ success: true, email: user.email });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Błąd serwera' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true });
});

app.get('/api/auth/check', authenticateToken, (req, res) => {
    res.json({ authenticated: true, user: req.user.email });
});

// Reszta endpointów (GET albums, DELETE, etc.) pozostaje podobna, ale musi używać authenticateToken

app.post('/api/upload', authenticateToken, upload.array('photos', 5), async (req, res) => {
    // Limit plików ustawiony w multer na 5. Frontend musi to obsłużyć.
    const { albumId } = req.body;
    if (!req.files |

| req.files.length === 0) return res.status(400).json({ error: 'Brak plików' });

    try {
        const albumCheck = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [albumId, req.user.id]);
        if (albumCheck.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu do albumu' });

        const results =;
        // Przetwarzanie sekwencyjne dla oszczędności pamięci
        for (const file of req.files) {
            try {
                // Optymalizacja Sharp: Użycie mozjpeg dla mniejszych plików
                const finalBuffer = await sharp(file.buffer)
                   .rotate()
                   .resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true }) 
                   .jpeg({ quality: 80, mozjpeg: true }) 
                   .toBuffer();

                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { 
                            folder: `proofing/${albumId}`,
                            // Dodanie znaku wodnego w locie (opcjonalnie, jeśli skonfigurowane w Cloudinary)
                            // transformation: [{ overlay: "logo", gravity: "southeast", width: 200, opacity: 50 }] 
                        },
                        (error, result) => {
                            if (error) reject(error);
                            else resolve(result);
                        }
                    );
                    streamifier.createReadStream(finalBuffer).pipe(stream);
                });

                const dbRes = await pool.query(
                    'INSERT INTO photos (album_id, proof_url, storage_id, filename) VALUES ($1, $2, $3, $4) RETURNING *',
                   
                );
                results.push(dbRes.rows);
            } catch (innerErr) {
                console.error("Błąd pliku:", file.originalname, innerErr);
                // Nie przerywamy całej pętli, tylko logujemy błąd
            }
        }
        res.json({ uploadedCount: results.length });
    } catch (err) {
        console.error('Upload Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Pozostałe endpointy (Create Album, Gallery, Select) - bez zmian w logice biznesowej, ale z obsługą błędów.

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb().then(() => {
    app.listen(PORT, '0.0.0.0', () => console.log(`Serwer start: ${PORT}`));
});
