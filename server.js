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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS';

// --- KONFIGURACJA ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Baza Danych
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 }
});

// Middleware Autoryzacji
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Brak autoryzacji' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token nieważny' });
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
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS selections (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE,
                photo_id UUID REFERENCES photos(id) ON DELETE CASCADE,
                UNIQUE(album_id, photo_id)
            );
        `);

        const userCheck = await client.query('SELECT * FROM users LIMIT 1');
        if (userCheck.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', ['admin@example.com', hash]);
            console.log('>>> UTWORZONO KONTO ADMINA: admin@example.com / admin123');
        }
    } catch (err) {
        console.error('Błąd Init DB:', err);
    } finally {
        client.release();
    }
};

// --- ROUTY (API) ---

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Błędny login lub hasło' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Błędny login lub hasło' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
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

// --- POPRAWIONY UPLOAD ---
app.post('/api/upload', authenticateToken, upload.array('photos'), async (req, res) => {
    const { albumId } = req.body;
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Brak plików' });

    try {
        const albumCheck = await pool.query('SELECT * FROM albums WHERE id=$1 AND user_id=$2', [albumId, req.user.id]);
        if (albumCheck.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });

        const results = [];
        
        for (const file of req.files) {
            // 1. Najpierw zmniejszamy zdjęcie
            const resizedBuffer = await sharp(file.buffer)
                .rotate()
                .resize({ width: 1200, height: 1200, fit: 'inside' })
                .toBuffer();

            // 2. Pobieramy wymiary zmniejszonego zdjęcia
            const metadata = await sharp(resizedBuffer).metadata();
            const { width, height } = metadata;

            // 3. Tworzymy znak wodny IDEALNIE dopasowany do wymiarów
            const svgWatermark = `
            <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
                <style>
                .txt { fill: rgba(255, 255, 255, 0.3); font-size: ${Math.min(width, height) * 0.15}px; font-weight: 800; font-family: sans-serif; transform: rotate(-30deg); transform-origin: center; }
                </style>
                <text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle" class="txt">PROOF ONLY</text>
            </svg>`;

            // 4. Nakładamy
            const finalBuffer = await sharp(resizedBuffer)
                .composite([{ input: Buffer.from(svgWatermark), gravity: 'center' }])
                .jpeg({ quality: 80 })
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
        }
        res.json({ uploaded: results });
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
        
        const selectedIds = selectionsRes.rows.map(r => r.photo_id);
        res.json({ album, photos: photosRes.rows, selections: selectedIds });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/select', async (req, res) => {
    const { token, photoIds } = req.body;
    const client = await pool.connect();
    try {
        const albumCheck = await client.query('SELECT id, status FROM albums WHERE access_token = $1', [token]);
        if (albumCheck.rows.length === 0) throw new Error('Błędny token');
        
        const albumId = albumCheck.rows[0].id;
        
        await client.query('BEGIN');
        await client.query('DELETE FROM selections WHERE album_id = $1', [albumId]);
        
        for (const pid of photoIds) {
            await client.query('INSERT INTO selections (album_id, photo_id) VALUES ($1, $2)', [albumId, pid]);
        }
        
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb().then(() => {
    app.listen(PORT, () => console.log(`Serwer start na porcie ${PORT}`));
});
