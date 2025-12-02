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

// --- WALIDACJA ŚRODOWISKA (NAPRAWIONA LINIA) ---
const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
requiredEnv.forEach(key => {
    if (!process.env[key]) {
        console.warn(`UWAGA: Brak zmiennej środowiskowej ${key}. Aplikacja może nie działać poprawnie.`);
    }
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PROD';

// --- KONFIGURACJA BEZPIECZEŃSTWA (CSP & HEADERS) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // POPRAWKA CSP (wcześniejsza): Dodano "blob:"
            scriptSrc: ["'self'", "'unsafe-inline'", "blob:"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            // NOWA POPRAWKA CSP: Dodano Google Analytics do connect-src
            connectSrc: ["'self'", "https://www.google-analytics.com"], 
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        },
    },
    crossOriginEmbedderPolicy: false
}));

// CORS i Cookies
app.use(cors({
    origin: process.env.APP_URL || 'http://localhost:3000', // W produkcji ustaw URL swojej aplikacji
    credentials: true // Zezwala na przesyłanie ciasteczek
}));

app.use(express.json({ limit: '10kb' })); // Ochrona przed dużym payloadem JSON
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- RATE LIMITING (Ochrona przed DDoS/Brute Force) ---
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
    max: 15, // Max 15 prób logowania na godzinę
    message: 'Zablokowano możliwość logowania na godzinę z powodu zbyt wielu prób.'
});

// --- BAZA DANYCH ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- CLOUDINARY ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- MULTER (Upload) ---
// Ograniczenie pamięci RAM: Max 5 plików na raz, max 10MB plik.
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024, files: 5 }
});

// --- EMAIL ---
const transporter = nodemailer.createTransport(new BrevoTransport({
    apiKey: process.env.BREVO_API_KEY || 'test'
}));

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

// --- INIT DB ---
const initDb = async () => {
    const client = await pool.connect();
    try {
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        
        // Dodano indeks na access_token dla wydajności galerii
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
        
        // Dodano indeks na album_id
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
            const initialPass = process.env.ADMIN_INITIAL_PASSWORD || 'admin123';
            const hash = await bcrypt.hash(initialPass, 10);
            await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', ['admin@example.com', hash]);
            
            // POPRAWKA BEZPIECZEŃSTWA: Usunięto logowanie hasła, dodano ostrzeżenie 
            if (initialPass === 'admin123') {
                console.warn('!!! UWAGA BEZPIECZEŃSTWA: Używasz domyślnego hasła "admin123". Ustaw silne ADMIN_INITIAL_PASSWORD w pliku .env!');
            }
            console.log('>>> ADMIN UTWORZONY. Dane: admin@example.com. Zmień hasło! (Hasło nie jest logowane do konsoli)');
        }
    } catch (err) {
        console.error('Błąd Init DB:', err);
    } finally {
        client.release();
    }
};

// --- API ---

// 1. Logowanie (Set-Cookie)
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Wymagane pola' });

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Błędne dane' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Błędne dane' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        // HTTP ONLY COOKIE - Kluczowe dla bezpieczeństwa
        res.cookie('auth_token', token, {
            httpOnly: true, // Niedostępne dla JS
            secure: process.env.NODE_ENV === 'production', // Tylko HTTPS w produkcji
            sameSite: 'strict',
            maxAge: 24 * 3600 * 1000 // 24h
        });

        res.json({ success: true, email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true });
});

// Endpoint do sprawdzania stanu sesji przez frontend
app.get('/api/auth/check', authenticateToken, (req, res) => {
    res.json({ authenticated: true, user: req.user.email });
});

app.get('/api/admin/albums', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.*, 
            COUNT(DISTINCT p.id) as photo_count,
            COUNT(DISTINCT s.id) as selection_count
            FROM albums a
            LEFT JOIN photos p ON a.id = p.album_id
            LEFT JOIN selections s ON a.id = s.album_id
            WHERE a.user_id = $1
            GROUP BY a.id ORDER BY created_at DESC
        `, [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/albums/:id/files', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`
            SELECT p.filename 
            FROM photos p
            JOIN selections s ON p.id = s.photo_id
            WHERE p.album_id = $1
        `, [id]);
        res.json({ filenames: result.rows.map(r => r.filename) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/albums', authenticateToken, async (req, res) => {
    // UWAGA: Wymagana dodatkowa sanitarazacja (czyszczenie) title i clientName, aby zapobiec XSS
    const { title, clientName } = req.body;
    const token = uuidv4().replace(/-/g, '').substring(0, 16);
    try {
        const result = await pool.query(
            'INSERT INTO albums (user_id, title, client_name, access_token) VALUES ($1, $2, $3, $4) RETURNING *',
            [req.user.id, title, clientName, token]
        );
        res.json(result.rows[0]); // Zwracamy obiekt, nie tablicę
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/albums/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const checkOwner = await pool.query('SELECT * FROM albums WHERE id = $1 AND user_id = $2', [id, req.user.id]);
        if (checkOwner.rows.length === 0) return res.status(403).json({ error: 'Brak uprawnień' });
        await pool.query('DELETE FROM albums WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ZMODYFIKOWANY UPLOAD (Oszczędność Pamięci)
app.post('/api/upload', authenticateToken, upload.array('photos', 5), async (req, res) => {
    const { albumId } = req.body;
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Brak plików' });

    try {
        const albumCheck = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [albumId, req.user.id]);
        if (albumCheck.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });

        const results = [];
        
        // Przetwarzanie sekwencyjne dla ochrony RAM
        for (const file of req.files) {
            try {
                // Resize i kompresja (mozjpeg)
                const finalBuffer = await sharp(file.buffer)
                    .rotate()
                    .resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true }) 
                    .jpeg({ quality: 80, mozjpeg: true }) 
                    .toBuffer();

                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { folder: `proofing/${albumId}` },
                        (error, result) => {
                            if (error) reject(error);
                            else resolve(result);
                        }
                    );
                    streamifier.createReadStream(finalBuffer).pipe(stream);
                });

                const dbRes = await pool.query(
                    'INSERT INTO photos (album_id, proof_url, storage_id, filename) VALUES ($1, $2, $3, $4) RETURNING *',
                    [albumId, uploadResult.secure_url, uploadResult.public_id, file.originalname]
                );
                results.push(dbRes.rows[0]);
            } catch (innerErr) {
                console.error("Błąd pliku:", file.originalname, innerErr);
            }
        }
        res.json({ uploadedCount: results.length });
    } catch (err) {
        console.error('Upload Error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/gallery/:token', async (req, res) => {
    try {
        const albumRes = await pool.query('SELECT id, title, client_name, status FROM albums WHERE access_token = $1', [req.params.token]);
        if (albumRes.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono' });
        const album = albumRes.rows;
        const photosRes = await pool.query('SELECT id, proof_url, filename FROM photos WHERE album_id = $1 ORDER BY filename', [album[0].id]);
        const selectionsRes = await pool.query('SELECT photo_id FROM selections WHERE album_id = $1', [album[0].id]);
        
        res.json({ album, photos: photosRes.rows, selections: selectionsRes.rows.map(r => r.photo_id) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/select', async (req, res) => {
    const { token, photoIds } = req.body;
    const client = await pool.connect();
    try {
        const albumCheck = await client.query('SELECT a.id, a.title, a.client_name FROM albums a WHERE access_token = $1', [token]);
        if (albumCheck.rows.length === 0) throw new Error('Błędny token');
        
        const album = albumCheck.rows[0];
        
        await client.query('BEGIN');
        await client.query('DELETE FROM selections WHERE album_id = $1', [album.id]);
        
        // UWAGA: Należy sprawdzić, czy photoIds zawiera ID faktycznie istniejące w danym albumie, 
        // aby zapobiec potencjalnemu atakowi SQL Injection / nieprawidłowym danym.
        for (const pid of photoIds) {
            await client.query('INSERT INTO selections (album_id, photo_id) VALUES ($1, $2)', [album.id, pid]);
        }
        await client.query('COMMIT');

        // Powiadomienie mailowe
        if (process.env.EMAIL_USER) {
             transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: process.env.EMAIL_USER, 
                subject: `📸 Klient ${album.client_name} zakończył wybór!`,
                text: `Klient w albumie "${album.title}" wybrał ${photoIds.length} zdjęć.`
            }).catch(e => console.error("Mail error:", e));
        }

        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/send-link', authenticateToken, async (req, res) => {
    // UWAGA: Wymagana sanitarazacja link i clientEmail.
    const { clientEmail, albumTitle, link } = req.body;
    if(!clientEmail) return res.status(400).json({ error: 'Brak maila' });

    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: clientEmail,
            subject: `Twoja galeria zdjęć: ${albumTitle}`,
            html: `
                <div style="font-family: sans-serif; padding: 20px; color: #333;">
                    <h2>Dzień dobry!</h2>
                    <p>Twoja galeria zdjęć z sesji <strong>${albumTitle}</strong> jest już gotowa.</p>
                    <a href="${link}" style="background: #c5a059; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">Otwórz Galerię</a>
                </div>
            `
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Błąd: ' + err.message });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb().then(() => {
    app.listen(PORT, '0.0.0.0', () => console.log(`Serwer Secure Photo Proofing działa na porcie ${PORT}`));
});
