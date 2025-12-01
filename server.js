// server.js - Wersja Poprawiona
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

// --- KONFIGURACJA ---
const app = express();
// Naprawiono błąd syntaxu: | | zamieniono na ||
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PRODUCTION_ENV';

// Middleware Bezpieczeństwa
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Konfiguracja Bazy Danych
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Konfiguracja Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Konfiguracja Multer
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 }
});

// --- MIDDLEWARE AUTORYZACJI ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // [1] bo format to "Bearer TOKEN"

    if (!token) return res.status(401).json({ error: 'Brak autoryzacji. Zaloguj się.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token nieważny lub wygasł.' });
        req.user = user;
        next();
    });
};

// --- INICJALIZACJA BAZY DANYCH ---
const initDb = async () => {
    try {
        const client = await pool.connect();
        await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);
        
        // Tabela Users
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        
        // Tabela Albums
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
        `);

        // Tabela Photos
        await client.query(`
            CREATE TABLE IF NOT EXISTS photos (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE,
                proof_url TEXT NOT NULL,
                storage_id VARCHAR(100),
                filename VARCHAR(255),
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // Tabela Selections
        await client.query(`
            CREATE TABLE IF NOT EXISTS selections (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE,
                photo_id UUID REFERENCES photos(id) ON DELETE CASCADE,
                UNIQUE(album_id, photo_id)
            );
        `);
        
        // Auto-Seed admina
        const userCheck = await client.query('SELECT * FROM users LIMIT 1');
        if (userCheck.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', ['admin@example.com', hash]);
            console.log('>>> UTWORZONO KONTO ADMINA: admin@example.com / admin123');
        }
        client.release(); // Ważne: zwolnienie klienta
    } catch (err) {
        console.error('Błąd inicjalizacji bazy:', err);
    }
};

// --- ENDPOINTY ---

// 1. Logowanie (TEN FRAGMENT BYŁ URWANY W ORYGINALE)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (result.rows.length === 0) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

        const user = result.rows[0]; // Poprawka: rows to tablica
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Dashboard
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

// 3. Tworzenie albumu
app.post('/api/albums', authenticateToken, async (req, res) => {
    const { title, clientName } = req.body;
    const token = uuidv4().replace(/-/g, '').substring(0, 16);

    try {
        const result = await pool.query(
            'INSERT INTO albums (user_id, title, client_name, access_token) VALUES ($1, $2, $3, $4) RETURNING *',
            [req.user.id, title, clientName, token]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Upload (Naprawiono błędy składni i logiki)
app.post('/api/upload', authenticateToken, upload.array('photos'), async (req, res) => {
    const { albumId } = req.body;
    // Naprawiono operator ||
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Brak plików' });

    const albumCheck = await pool.query('SELECT * FROM albums WHERE id = $1 AND user_id = $2', [albumId, req.user.id]);
    if (albumCheck.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu do tego albumu' });

    const results = []; // Naprawiono puste przypisanie
    const errors = [];  // Naprawiono puste przypisanie

    for (const file of req.files) {
        try {
            const width = 1200; 
            const svgWatermark = `
                <svg width="${width}" height="${width}" viewBox="0 0 ${width} ${width}">
                <style>
                   .txt { fill: rgba(255, 255, 255, 0.25); font-size: 80px; font-weight: 800; font-family: sans-serif; transform: rotate(-45deg); transform-origin: center; }
                </style>
                <text x="50%" y="50%" text-anchor="middle" class="txt">PROOF ONLY</text>
                </svg>`;

            const processedBuffer = await sharp(file.buffer)
               .rotate()
               .resize({ width: 1200, height: 1200, fit: 'inside' })
               .composite([{ input: Buffer.from(svgWatermark), blend: 'over' }]) // Poprawiona składnia composite
               .jpeg({ quality: 80, mozjpeg: true })
               .toBuffer();

            const uploadResult = await new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    { folder: `proofing/${albumId}`, public_id: uuidv4() },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                streamifier.createReadStream(processedBuffer).pipe(uploadStream);
            });

            // Naprawiono brakujące parametry w zapytaniu SQL
            const dbRes = await pool.query(
                'INSERT INTO photos (album_id, proof_url, storage_id, filename) VALUES ($1, $2, $3, $4) RETURNING *',
                [albumId, uploadResult.secure_url, uploadResult.public_id, file.originalname]
            );
            results.push(dbRes.rows[0]);

        } catch (err) {
            console.error(`Błąd pliku ${file.originalname}:`, err);
            errors.push({ file: file.originalname, error: err.message });
        }
    }

    res.json({ uploaded: results, errors: errors });
});

// 5. Widok Klienta
app.get('/api/gallery/:token', async (req, res) => {
    try {
        const albumRes = await pool.query('SELECT id, title, client_name, status FROM albums WHERE access_token = $1', [req.params.token]);
        if (albumRes.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono galerii lub link jest nieprawidłowy' });

        const album = albumRes.rows[0]; // Poprawka: rows[0]
        
        const photosRes = await pool.query('SELECT id, proof_url, filename FROM photos WHERE album_id = $1 ORDER BY filename', [album.id]);
        
        const selectionsRes = await pool.query('SELECT photo_id FROM selections WHERE album_id = $1', [album.id]);
        const selectedIds = selectionsRes.rows.map(r => r.photo_id);

        res.json({ album, photos: photosRes.rows, selections: selectedIds });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Zapis Wyboru Klienta
app.post('/api/select', async (req, res) => {
    const { token, photoIds } = req.body;

    const client = await pool.connect();
    try {
        const albumCheck = await client.query('SELECT id, status FROM albums WHERE access_token = $1', [token]);
        if (albumCheck.rows.length === 0) throw new Error('Nieprawidłowy token');
        
        const album = albumCheck.rows[0]; // Poprawka: rows[0]
        const albumId = album.id;
        
        if (album.status !== 'active') throw new Error('Galeria została zamknięta przez fotografa');

        await client.query('BEGIN');
        await client.query('DELETE FROM selections WHERE album_id = $1', [albumId]);

        if (photoIds && photoIds.length > 0) {
            for (const pid of photoIds) {
                await client.query('INSERT INTO selections (album_id, photo_id) VALUES ($1, $2)', [albumId, pid]);
            }
        }

        await client.query('COMMIT');
        res.json({ message: 'Zapisano wybór', count: photoIds ? photoIds.length : 0 });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

// SPA Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Serwera
initDb().then(() => {
    app.listen(PORT, () => console.log(`Serwer uruchomiony na porcie ${PORT}`));
});
