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
const archiver = require('archiver'); // PAMIĘTAJ O DODANIU DO package.json

// --- WALIDACJA ZMIENNYCH ---
const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'GCS_BUCKET_NAME', 'GCS_PROJECT_ID', 'BREVO_API_KEY', 'EMAIL_USER'];
requiredEnv.forEach(key => {
    if (!process.env[key]) console.warn(`⚠️ UWAGA: Brak zmiennej ${key}`);
});

const app = express();
// --- POPRAWKA DLA RENDER ---
app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PROD';

// --- GCS CONFIG ---
let storage;
const BUCKET_NAME = process.env.GCS_BUCKET_NAME;

if (process.env.GOOGLE_CREDENTIALS_BASE64) {
    try {
        const credentials = JSON.parse(
            Buffer.from(process.env.GOOGLE_CREDENTIALS_BASE64, 'base64').toString()
        );
        storage = new Storage({ projectId: process.env.GCS_PROJECT_ID, credentials });
        console.log('✅ GCS: Zalogowano (Base64)');
    } catch (e) { console.error('❌ Błąd klucza GCS:', e); }
} else {
    storage = new Storage({ projectId: process.env.GCS_PROJECT_ID });
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

// --- DB ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- UPLOAD CONFIG ---
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024, files: 5 } }); // Zwiększyłem limit pliku do 25MB (dla RAW/dużych JPG)

// --- MAIL TRANSPORTER ---
const transporter = nodemailer.createTransport(new BrevoTransport({ apiKey: process.env.BREVO_API_KEY }));

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Brak autoryzacji' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).clearCookie('auth_token').json({ error: 'Sesja wygasła' });
        req.user = user;
        next();
    });
};

// --- ENDPOINTY SYSTEMOWE ---

app.post('/api/auth/login', async (req, res) => {
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

// --- ENDPOINTY APLIKACJI ---

// 1. Pobieranie albumów
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

// 2. Tworzenie albumu
app.post('/api/albums', authenticateToken, async (req, res) => {
    const { title, clientName } = req.body;
    const token = uuidv4().replace(/-/g, '').substring(0, 16);
    try {
        const result = await pool.query('INSERT INTO albums (user_id, title, client_name, access_token) VALUES ($1, $2, $3, $4) RETURNING *', [req.user.id, title, clientName, token]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. Usuwanie albumu
app.delete('/api/albums/:id', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });
        // Uwaga: To usuwa wpisy z bazy. Pliki w GCS zostają (to bezpieczniejsze, żeby przypadkiem nie usunąć czegoś ważnego).
        // Można dodać usuwanie plików z GCS, ale to bardziej skomplikowane.
        await pool.query('DELETE FROM albums WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. UPLOAD (NOWA WERSJA: DUAL UPLOAD)
app.post('/api/upload', authenticateToken, upload.array('photos', 5), async (req, res) => {
    const { albumId } = req.body;
    if (!req.files?.length) return res.status(400).json({ error: 'Brak plików' });

    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [albumId, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });

        const results = [];
        
        for (const file of req.files) {
            try {
                const fileId = uuidv4();
                const ext = path.extname(file.originalname).toLowerCase();
                
                // A. WERSJA PROOF (Lekka, do galerii)
                const proofBuffer = await sharp(file.buffer)
                    .rotate()
                    .resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true })
                    .jpeg({ quality: 80, mozjpeg: true })
                    .toBuffer();

                const proofFilename = `albums/${albumId}/${fileId}${ext}`;
                const proofFile = bucket.file(proofFilename);
                await proofFile.save(proofBuffer, { contentType: 'image/jpeg', resumable: false });
                
                const publicUrl = `https://storage.googleapis.com/${BUCKET_NAME}/${proofFilename}`;

                // B. WERSJA FULL (Oryginał, do ZIPa)
                const originalBuffer = await sharp(file.buffer)
                    .rotate() 
                    .jpeg({ quality: 100, mozjpeg: false }) 
                    .toBuffer();

                const originalFilename = `albums/${albumId}/${fileId}_full${ext}`;
                const originalFile = bucket.file(originalFilename);
                await originalFile.save(originalBuffer, { contentType: 'image/jpeg', resumable: false });

                // C. ZAPIS W BAZIE (Wskazujemy na Proof!)
                const dbRes = await pool.query(
                    'INSERT INTO photos (album_id, proof_url, storage_id, filename) VALUES ($1, $2, $3, $4) RETURNING *',
                    [albumId, publicUrl, proofFilename, file.originalname]
                );
                results.push(dbRes.rows[0]);

            } catch (e) { console.error("Błąd pliku:", e); }
        }
        res.json({ uploadedCount: results.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. Wysyłanie Linku do Galerii (Początkowe)
app.post('/api/send-link', authenticateToken, async (req, res) => {
    const { clientEmail, albumTitle, link } = req.body;
    if (!clientEmail || !link) return res.status(400).json({ error: 'Brak danych' });
    try {
        const sender = process.env.EMAIL_USER;
        if (!sender) return res.status(500).json({error: 'Brak EMAIL_USER'});

        await transporter.sendMail({
            from: `Julia Berlik Foto <${sender}>`,
            to: clientEmail,
            subject: `Twoja sesja: ${albumTitle} - Wybór Zdjęć`,
            html: `
                <div style="font-family:sans-serif; padding:20px; color:#333;">
                    <h2>Witaj!</h2>
                    <p>Zdjęcia z sesji <strong>"${albumTitle}"</strong> są gotowe.</p>
                    <a href="${link}" style="display:inline-block; background:#c5a059; color:white; padding:10px 20px; text-decoration:none; border-radius:4px; margin-top:10px;">Otwórz Galerię</a>
                </div>
            `
        });
        res.json({ success: true });
    } catch (err) {
        console.error("Błąd wysyłki:", err);
        res.status(500).json({ error: err.message || 'Błąd wysyłki' });
    }
});

// 6. Galeria Klienta (Publiczna)
app.get('/api/gallery/:token', async (req, res) => {
    try {
        const alb = await pool.query('SELECT * FROM albums WHERE access_token=$1', [req.params.token]);
        if (alb.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono' });
        const photos = await pool.query('SELECT id, proof_url, filename FROM photos WHERE album_id=$1 ORDER BY filename', [alb.rows[0].id]);
        const sels = await pool.query('SELECT photo_id FROM selections WHERE album_id=$1', [alb.rows[0].id]);
        res.json({ album: alb.rows, photos: photos.rows, selections: sels.rows.map(s => s.photo_id) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 7. Zapisywanie Wyboru Klienta
app.post('/api/select', async (req, res) => {
    const { token, photoIds } = req.body;
    const client = await pool.connect();
    try {
        const alb = await client.query('SELECT id, title, client_name FROM albums WHERE access_token=$1', [token]);
        if (!alb.rows.length) throw new Error('Błąd tokena');
        await client.query('BEGIN');
        await client.query('DELETE FROM selections WHERE album_id=$1', [alb.rows[0].id]);
        for (const pid of photoIds) await client.query('INSERT INTO selections (album_id, photo_id) VALUES ($1, $2)', [alb.rows[0].id, pid]);
        await client.query('COMMIT');
        
        if (process.env.EMAIL_USER) {
            transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: process.env.EMAIL_USER,
                subject: `📸 Wybór: ${alb.rows[0].client_name}`,
                text: `Wybrano ${photoIds.length} zdjęć.`
            }).catch(e => console.error("Mail powiadomienie błąd:", e));
        }
        res.json({ success: true });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } finally { client.release(); }
});

// 8. AUTOMATYCZNE PAKOWANIE (ZIP - Obsługuje Full Res i Fallback)
app.post('/api/auto-deliver', authenticateToken, async (req, res) => {
    const { albumId } = req.body;
    req.setTimeout(600000); // 10 minut na spakowanie

    try {
        const albRes = await pool.query('SELECT * FROM albums WHERE id=$1', [albumId]);
        if (albRes.rows.length === 0) return res.status(404).json({ error: 'Album nie istnieje' });
        const album = albRes.rows[0];

        const selRes = await pool.query(
            'SELECT p.storage_id, p.filename FROM selections s JOIN photos p ON s.photo_id = p.id WHERE s.album_id=$1',
            [albumId]
        );

        if (selRes.rows.length === 0) return res.status(400).json({ error: 'Brak wybranych zdjęć!' });

        const zipName = `zips/${album.access_token}_photos.zip`;
        const zipFile = bucket.file(zipName);
        const outputStream = zipFile.createWriteStream({ resumable: false });
        
        // Używamy store:true dla szybkości (JPG już są skompresowane)
        const archive = archiver('zip', { store: true }); 

        archive.on('error', err => { throw err; });
        archive.pipe(outputStream);

        console.log(`>>> Pakowanie ${selRes.rows.length} zdjęć...`);

        for (const photo of selRes.rows) {
            // Logika: Szukamy _full. Jak nie ma, bierzemy proof.
            const ext = path.extname(photo.storage_id);
            const base = photo.storage_id.substring(0, photo.storage_id.length - ext.length);
            
            const fullResPath = `${base}_full${ext}`;
            const fileRef = bucket.file(fullResPath);

            // Sprawdzamy istnienie Full Res
            const [exists] = await fileRef.exists();

            if (exists) {
                archive.append(fileRef.createReadStream(), { name: photo.filename });
            } else {
                // Fallback dla starych sesji
                const proofRef = bucket.file(photo.storage_id);
                archive.append(proofRef.createReadStream(), { name: photo.filename });
            }
        }

        await archive.finalize();

        await new Promise((resolve, reject) => {
            outputStream.on('finish', resolve);
            outputStream.on('error', reject);
        });

        const publicUrl = `https://storage.googleapis.com/${BUCKET_NAME}/${zipName}`;
        res.json({ success: true, downloadLink: publicUrl, count: selRes.rows.length });

    } catch (err) {
        console.error("Błąd pakowania:", err);
        res.status(500).json({ error: 'Błąd ZIP: ' + err.message });
    }
});

// 9. Wysyłka gotowego ZIPa (Mail z linkiem)
app.post('/api/send-delivery', authenticateToken, async (req, res) => {
    const { clientEmail, albumTitle, downloadLink, clientName } = req.body;
    if (!clientEmail || !downloadLink) return res.status(400).json({ error: 'Brak danych' });

    try {
        const sender = process.env.EMAIL_USER;
        await transporter.sendMail({
            from: `Julia Berlik Foto <${sender}>`,
            to: clientEmail,
            subject: `🎁 Gotowe zdjęcia: ${albumTitle}`,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; text-align: center; color: #333;">
                    <h2 style="color: #1a1a1a;">Dzień dobry, ${clientName || ''}!</h2>
                    <p>Twoje wybrane zdjęcia z sesji <strong>"${albumTitle}"</strong> są gotowe do pobrania.</p>
                    <div style="margin: 30px 0;">
                        <a href="${downloadLink}" style="background-color: #c5a059; color: #ffffff; padding: 15px 30px; text-decoration: none; font-weight: bold; border-radius: 4px;">POBIERZ PACZKĘ (.ZIP)</a>
                    </div>
                    <p style="font-size: 12px; color: #888;">Link bezpośredni: ${downloadLink}</p>
                </div>
            `
        });
        res.json({ success: true });
    } catch (err) {
        console.error("Błąd wysyłki gotowych:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- INIT ---
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
        }
    } catch (e) { console.error(e); } finally { client.release(); }
};

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
initDb().then(() => app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`)));
