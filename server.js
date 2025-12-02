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
const archiver = require('archiver');

// --- WALIDACJA ZMIENNYCH ---
const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'GCS_BUCKET_NAME', 'GCS_PROJECT_ID', 'BREVO_API_KEY', 'EMAIL_USER', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'];
requiredEnv.forEach(key => {
    if (!process.env[key]) console.warn(`⚠️ UWAGA: Brak zmiennej ${key}`);
});

const app = express();
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
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024, files: 5 } });

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

// --- RATE LIMITING ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minut
    max: 100,
    message: 'Zbyt wiele żądań, spróbuj później'
});

app.use('/api/', apiLimiter);

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

// 1.5. Pobieranie listy nazw plików
app.get('/api/admin/albums/:id/files', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });
        const result = await pool.query('SELECT filename FROM photos WHERE album_id=$1 ORDER BY filename', [req.params.id]);
        res.json({ filenames: result.rows.map(r => r.filename) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Tworzenie albumu (POPRAWIONE)
app.post('/api/albums', authenticateToken, async (req, res) => {
    const { title, clientName, clientEmail } = req.body;
    const token = uuidv4().replace(/-/g, '').substring(0, 16);
    
    console.log('>>> Tworzenie albumu:', { title, clientName, clientEmail }); // DEBUG
    
    try {
        const result = await pool.query(
            'INSERT INTO albums (user_id, title, client_name, client_email, access_token) VALUES ($1, $2, $3, $4, $5) RETURNING *', 
            [req.user.id, title, clientName, clientEmail || null, token]
        );
        console.log('>>> Album utworzony:', result.rows[0]); // DEBUG
        res.json(result.rows[0]);
    } catch (err) { 
        console.error('>>> Błąd tworzenia albumu:', err); // DEBUG
        res.status(500).json({ error: err.message }); 
    }
});

// 3. Usuwanie albumu
app.delete('/api/albums/:id', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT id FROM albums WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Brak dostępu' });
        await pool.query('DELETE FROM albums WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. UPLOAD (DUAL UPLOAD: PROOF + FULL)
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

                // C. ZAPIS W BAZIE
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

// 5. Wysyłanie Linku do Galerii
app.post('/api/send-link', authenticateToken, async (req, res) => {
    const { clientEmail, albumTitle, link } = req.body;
    if (!clientEmail || !link) return res.status(400).json({ error: 'Brak danych' });
    
    try {
        const sender = process.env.EMAIL_USER;
        if (!sender) return res.status(500).json({error: 'Brak EMAIL_USER'});

        // Aktualizuj album z emailem klienta (jeśli nie był zapisany)
        const tokenMatch = link.match(/\/gallery\/([a-z0-9]+)/);
        if (tokenMatch) {
            await pool.query(
                'UPDATE albums SET client_email = $1 WHERE access_token = $2 AND client_email IS NULL',
                [clientEmail, tokenMatch[1]]
            );
        }

        await transporter.sendMail({
            from: `Julia Berlik Foto <${sender}>`,
            to: clientEmail,
            subject: `Twoja sesja: ${albumTitle} - Wybór Zdjęć`,
            html: `
                <div style="font-family:sans-serif; padding:20px; color:#333; max-width:600px; margin:0 auto;">
                    <div style="text-align:center; margin-bottom:30px;">
                        <h1 style="font-family:'Cinzel', serif; color:#1a1a1a; letter-spacing:2px;">Julia Berlik <span style="color:#c5a059;">Foto</span></h1>
                    </div>
                    <h2 style="color:#c5a059;">Witaj!</h2>
                    <p style="line-height:1.8;">Zdjęcia z Twojej sesji <strong>"${albumTitle}"</strong> są gotowe do przeglądania.</p>
                    <p style="line-height:1.8;">Kliknij poniższy przycisk, aby otworzyć galerię i wybrać swoje ulubione zdjęcia:</p>
                    <div style="text-align:center; margin:30px 0;">
                        <a href="${link}" style="display:inline-block; background:#c5a059; color:white; padding:15px 40px; text-decoration:none; border-radius:8px; font-weight:600; font-size:16px;">Otwórz Galerię</a>
                    </div>
                    <p style="color:#666; font-size:14px; line-height:1.6;">💡 <strong>Jak to działa?</strong></p>
                    <ul style="color:#666; font-size:14px; line-height:1.8;">
                        <li>Kliknij serce ❤ na zdjęciach, które Ci się podobają</li>
                        <li>Możesz przeglądać zdjęcia w trybie pełnoekranowym</li>
                        <li>Po zakończeniu wyboru kliknij "Zatwierdź Wybór"</li>
                    </ul>
                    <p style="color:#999; font-size:12px; margin-top:30px; border-top:1px solid #eee; padding-top:20px;">Zapisz ten link, aby wrócić do galerii: ${link}</p>
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
                text: `Klient ${alb.rows[0].client_name} wybrał ${photoIds.length} zdjęć z sesji "${alb.rows[0].title}".`
            }).catch(e => console.error("Mail powiadomienie błąd:", e));
        }
        res.json({ success: true });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } finally { client.release(); }
});

// 8. AUTOMATYCZNE PAKOWANIE (ZIP)
app.post('/api/auto-deliver', authenticateToken, async (req, res) => {
    const { albumId } = req.body;
    req.setTimeout(600000); // 10 minut

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
        const archive = archiver('zip', { store: true });

        archive.on('error', err => { throw err; });
        archive.pipe(outputStream);

        console.log(`>>> Pakowanie ${selRes.rows.length} zdjęć...`);

        for (const photo of selRes.rows) {
            const ext = path.extname(photo.storage_id);
            const base = photo.storage_id.substring(0, photo.storage_id.length - ext.length);
            const fullResPath = `${base}_full${ext}`;
            const fileRef = bucket.file(fullResPath);
            const [exists] = await fileRef.exists();

            if (exists) {
                archive.append(fileRef.createReadStream(), { name: photo.filename });
            } else {
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

// 9. Wysyłka gotowego ZIPa
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
                <div style="font-family: Arial, sans-serif; padding: 20px; text-align: center; color: #333; max-width:600px; margin:0 auto;">
                    <div style="margin-bottom:30px;">
                        <h1 style="font-family:'Cinzel', serif; color:#1a1a1a; letter-spacing:2px;">Julia Berlik <span style="color:#c5a059;">Foto</span></h1>
                    </div>
                    <h2 style="color: #1a1a1a;">Dzień dobry${clientName ? ', ' + clientName : ''}!</h2>
                    <p style="line-height:1.8;">Twoje wybrane zdjęcia z sesji <strong>"${albumTitle}"</strong> są gotowe do pobrania.</p>
                    <div style="margin: 30px 0;">
                        <a href="${downloadLink}" style="background-color: #c5a059; color: #ffffff; padding: 15px 40px; text-decoration: none; font-weight: bold; border-radius: 8px; display:inline-block; font-size:16px;">POBIERZ PACZKĘ (.ZIP)</a>
                    </div>
                    <p style="color:#666; font-size:14px; line-height:1.6;">📦 Wszystkie zdjęcia są w pełnej rozdzielczości, bez znaków wodnych.</p>
                    <p style="color:#999; font-size:12px; margin-top:30px; border-top:1px solid #eee; padding-top:20px;">Link: ${downloadLink}</p>
                </div>
            `
        });
        res.json({ success: true });
    } catch (err) {
        console.error("Błąd wysyłki gotowych:", err);
        res.status(500).json({ error: err.message });
    }
});

// 10. WYSZUKIWANIE SESJI KLIENTA
app.post('/api/sessions/lookup', async (req, res) => {
    const { email } = req.body;
    
    if (!email) return res.status(400).json({ error: 'Brak adresu email' });
    
    try {
        const result = await pool.query(`
            SELECT 
                a.id,
                a.title,
                a.client_name,
                a.client_email,
                a.access_token,
                a.created_at,
                COUNT(DISTINCT p.id) as photo_count,
                COUNT(DISTINCT s.id) as selection_count
            FROM albums a
            LEFT JOIN photos p ON a.id = p.album_id
            LEFT JOIN selections s ON a.id = s.album_id
            WHERE 
                LOWER(a.client_email) = LOWER($1)
                OR LOWER(a.client_name) LIKE LOWER($2)
            GROUP BY a.id
            ORDER BY a.created_at DESC
            LIMIT 20
        `, [email, `%${email.split('@')[0]}%`]);
        
        res.json(result.rows);
        
    } catch (err) {
        console.error('Błąd wyszukiwania sesji:', err);
        res.status(500).json({ error: 'Błąd wyszukiwania sesji' });
    }
});

// --- INIT & DATABASE MIGRATION ---
const initDb = async () => {
    const client = await pool.connect();
    try {
        console.log('🔄 Inicjalizacja bazy danych...');
        
        // Tworzenie rozszerzeń i tabel
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
                email VARCHAR(255) UNIQUE, 
                password_hash VARCHAR(255)
            )
        `);
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS albums (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
                user_id UUID REFERENCES users(id), 
                title VARCHAR(200), 
                client_name VARCHAR(100), 
                access_token VARCHAR(64) UNIQUE, 
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        
        // MIGRACJA: Dodaj kolumnę client_email jeśli nie istnieje
        try {
            await client.query(`
                ALTER TABLE albums 
                ADD COLUMN IF NOT EXISTS client_email VARCHAR(255)
            `);
            console.log('✅ Kolumna client_email dodana/istnieje');
        } catch (e) {
            console.log('ℹ️ Kolumna client_email już istnieje lub błąd migracji:', e.message);
        }
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS photos (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE, 
                proof_url TEXT, 
                storage_id VARCHAR(100), 
                filename VARCHAR(255)
            )
        `);
        
        await client.query(`
            CREATE TABLE IF NOT EXISTS selections (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
                album_id UUID REFERENCES albums(id) ON DELETE CASCADE, 
                photo_id UUID REFERENCES photos(id) ON DELETE CASCADE, 
                UNIQUE(album_id, photo_id)
            )
        `);
        
        // 🔐 TWORZENIE KONTA FOTOGRAFA Z ZMIENNYCH ŚRODOWISKOWYCH
        if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
            const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
            
            if (existingUser.rows.length === 0) {
                // Utwórz nowe konto
                const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
                await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [process.env.ADMIN_EMAIL, hash]);
                console.log(`✅ Utworzono konto fotografa: ${process.env.ADMIN_EMAIL}`);
            } else {
                // Zaktualizuj hasło jeśli użytkownik już istnieje
                const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
                await client.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hash, process.env.ADMIN_EMAIL]);
                console.log(`✅ Zaktualizowano hasło dla: ${process.env.ADMIN_EMAIL}`);
            }
        } else {
            console.warn('⚠️ UWAGA: Brak ADMIN_EMAIL i ADMIN_PASSWORD w zmiennych środowiskowych!');
            console.warn('⚠️ Dodaj te zmienne, aby móc się zalogować do panelu fotografa.');
        }
        
        console.log('✅ Baza danych zainicjalizowana');
    } catch (e) { 
        console.error('❌ Błąd inicjalizacji bazy:', e); 
    } finally { 
        client.release(); 
    }
};

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

initDb().then(() => {
    app.listen(PORT, () => {
        console.log(`\n🚀 Server uruchomiony na porcie ${PORT}`);
        console.log(`📸 Julia Berlik Foto - System Proofingu`);
        console.log(`🌐 ${process.env.APP_URL || 'http://localhost:' + PORT}`);
        if (process.env.ADMIN_EMAIL) {
            console.log(`🔐 Login: ${process.env.ADMIN_EMAIL}`);
        }
        console.log('');
    });
});