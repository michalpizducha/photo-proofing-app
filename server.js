require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const { Storage } = require('@google-cloud/storage');
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

// --- WALIDACJA ZMIENNYCH ---
const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'GCS_BUCKET_NAME', 'GCS_PROJECT_ID'];
requiredEnv.forEach(key => {
    if (!process.env[key]) console.warn(`⚠️ UWAGA: Brak zmiennej ${key}`);
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PROD';

// --- KONFIGURACJA GOOGLE STORAGE (DLA RENDER & BASE64) ---
let storage;
const BUCKET_NAME = process.env.GCS_BUCKET_NAME;

if (process.env.GOOGLE_CREDENTIALS_BASE64) {
    try {
        // Dekodujemy klucz z Base64 (to co ustawiłaś w Renderze)
        const credentials = JSON.parse(
            Buffer.from(process.env.GOOGLE_CREDENTIALS_BASE64, 'base64').toString()
        );
        storage = new Storage({
            projectId: process.env.GCS_PROJECT_ID,
            credentials: credentials
        });
        console.log('✅ GCS: Zalogowano poprawnie (Render Base64)');
    } catch (e) {
        console.error('❌ Błąd klucza GCS:', e);
    }
} else {
    // Fallback dla testów lokalnych (jeśli będziesz kiedyś potrzebować)
    storage = new Storage({ projectId: process.env.GCS_PROJECT_ID });
    console.log('ℹ️ GCS: Tryb domyślny');
}

const bucket = storage.bucket(BUCKET_NAME);

// --- BEZPIECZEŃSTWO ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "blob:"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            // Zezwalamy na zdjęcia z Google Storage
            imgSrc: ["'self'", "data:", "https://storage.googleapis.com"],
            connectSrc: ["'self'", "https://www.google-analytics.com"], 
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        },
    },
    crossOriginEmbedderPolicy: false
}));

app.use(cors({ origin: process.env.APP_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- LIMITY ---
app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 200 })); // API limit
const authLimiter = rateLimit({ windowMs: 60*60*1000, max: 15, message: 'Za dużo prób logowania.' });

// --- BAZA DANYCH ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- UPLOAD (MULTER) ---
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024, files: 5 } // Max 10MB
});

// --- EMAIL ---
const transporter = nodemailer.createTransport(new BrevoTransport({ apiKey: process.env.BREVO_API_KEY || 'test' }));

// --- MIDDLEWARE AUTH ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Brak autoryzacji' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).clearCookie('auth_token').json({ error: 'Sesja wygasła' });
        req.user = user;
        next();
    });
};

// --- API: LOGOWANIE ---
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Błędne dane' });
        
        const user = result.rows[0];
        if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Błędne dane' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('auth_token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 86400000 });
        res.json({ success: true, email: user.email });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('auth_token').json({ success: true }); });
app.get('/api/auth/check', authenticateToken, (req, res) => { res.json({ authenticated: true, user: req.user.email }); });

// --- API: ALBUMY ---
app.get('/api/admin/albums', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.*, COUNT(DISTINCT p.id) as photo_count, COUNT(DISTINCT s.id) as selection_count
            FROM albums a LEFT JOIN photos p ON a.id = p.album_id LEFT JOIN selections s ON a.id = s.album_id
            WHERE a.user_id = $1 GROUP BY a.id ORDER BY created_at DESC
        `, [req.user.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/albums', authenticateToken, async (req, res) => {
    const { title, clientName } = req.body;
    const token = uuidv4().replace(/-/g, '').substring(0, 16);
    try {
        const result = await pool.query(
            'INSERT INTO albums (user_id, title, client_name, access_token) VALUES ($1, $2, $3, $4) RETURNING *',
            [req.user.id, title, clientName, token]
        );
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/albums/:id', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });
        await pool.query('DELETE FROM albums WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- API: UPLOAD (GOOGLE STORAGE) ---
app.post('/api/upload', authenticateToken, upload.array('photos', 5), async (req, res) => {
    const { albumId } = req.body;
    if (!req.files?.length) return res.status(400).json({ error: 'Brak plików' });

    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [albumId, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });

        const results = [];
        for (const file of req.files) {
            try {
                // 1. Sharp (Kompresja)
                const buffer = await sharp(file.buffer)
                    .rotate().resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true })
                    .jpeg({ quality: 80, mozjpeg: true }).toBuffer();

                // 2. Upload do GCS
                const ext = path.extname(file.originalname).toLowerCase();
                const filename = `albums/${albumId}/${uuidv4()}${ext}`;
                const blob = bucket.file(filename);
                
                await blob.save(buffer, { contentType: file.mimetype, resumable: false });

                // 3. Link publiczny
                const publicUrl = `https://storage.googleapis.com/${BUCKET_NAME}/${filename}`;

                // 4. Baza
                const dbRes = await pool.query(
                    'INSERT INTO photos (album_id, proof_url, storage_id, filename) VALUES ($1, $2, $3, $4) RETURNING *',
                    [albumId, publicUrl, filename, file.originalname]
                );
                results.push(dbRes.rows[0]);
            } catch (e) { console.error("Błąd pliku:", e); }
        }
        res.json({ uploadedCount: results.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- API: GALERIA KLIENTA ---
app.get('/api/gallery/:token', async (req, res) => {
    try {
        const alb = await pool.query('SELECT * FROM albums WHERE access_token=$1', [req.params.token]);
        if (alb.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono' });
        
        const photos = await pool.query('SELECT id, proof_url, filename FROM photos WHERE album_id=$1 ORDER BY filename', [alb.rows[0].id]);
        const sels = await pool.query('SELECT photo_id FROM selections WHERE album_id=$1', [alb.rows[0].id]);
        
        res.json({ album: alb.rows, photos: photos.rows, selections: sels.rows.map(s => s.photo_id) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/select', async (req, res) => {
    const { token, photoIds } = req.body;
    const client = await pool.connect();
    try {
        const alb = await client.query('SELECT id, title, client_name FROM albums WHERE access_token=$1', [token]);
        if (alb.rows.length === 0) throw new Error('Błędny token');
        
        await client.query('BEGIN');
        await client.query('DELETE FROM selections WHERE album_id=$1', [alb.rows[0].id]);
        for (const pid of photoIds) {
            await client.query('INSERT INTO selections (album_id, photo_id) VALUES ($1, $2)', [alb.rows[0].id, pid]);
        }
        await client.query('COMMIT');

        // Powiadomienie
        if (process.env.EMAIL_USER) {
            transporter.sendMail({
                from: process.env.EMAIL_USER, to: process.env.EMAIL_USER,
                subject: `📸 Wybór zakończony: ${alb.rows[0].client_name}`,
                text: `Klient wybrał ${photoIds.length} zdjęć w albumie "${alb.rows[0].title}".`
            }).catch(console.error);
        }
        res.json({ success: true });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } 
    finally { client.release(); }
});

// --- INIT DB & START ---
const initDb = async () => {
    const client = await pool.connect();
    try {
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
        await client.query(`CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email VARCHAR(255) UNIQUE, password_hash VARCHAR(255))`);
        await client.query(`CREATE TABLE IF NOT EXISTS albums (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID REFERENCES users(id), title VARCHAR(200), client_name VARCHAR(100), access_token VARCHAR(64) UNIQUE, created_at TIMESTAMP DEFAULT NOW())`);
        await client.query(`CREATE TABLE IF NOT EXISTS photos (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), album_id UUID REFERENCES albums(id) ON DELETE CASCADE, proof_url TEXT, storage_id VARCHAR(100), filename VARCHAR(255))`);
        await client.query(`CREATE TABLE IF NOT EXISTS selections (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), album_id UUID REFERENCES albums(id) ON DELETE CASCADE, photo_id UUID REFERENCES photos(id) ON DELETE CASCADE, UNIQUE(album_id, photo_id))`);
        
        const admin = await client.query('SELECT * FROM users LIMIT 1');
        if (admin.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', ['admin@example.com', hash]);
            console.log('>>> ADMIN UTWORZONY: admin@example.com / admin123');
        }
    } catch (e) { console.error(e); } finally { client.release(); }
};

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

initDb().then(() => app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`)));
