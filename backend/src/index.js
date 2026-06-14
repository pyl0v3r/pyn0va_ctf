// Required modules

const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const multer = require('multer');
// Ensure database and table exist
const dbConfig = {
    host: 'localhost',
    user: 'root', // change as needed
    password: '' // change as needed
};

const dbName = 'ctf';

const dbInit = mysql.createConnection(dbConfig);
dbInit.connect((err) => {
    if (err) {
        console.error('MySQL connection error:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL server.');
    dbInit.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``, (err) => {
        if (err) {
            console.error('Error creating database:', err);
            process.exit(1);
        }
        dbInit.changeUser({ database: dbName }, (err) => {
            if (err) {
                console.error('Error switching to database:', err);
                process.exit(1);
            }
            dbInit.query(`CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(32) NOT NULL DEFAULT 'user'
            )`, (err) => {
                if (err) {
                    console.error('Error creating users table:', err);
                    process.exit(1);
                }
                console.log('Database and users table ready.');
            });
        });
    });
});
const app = express();
const PORT = 8000;
const JWT_SECRET = 'supersecretkey'; // Change this in production

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Ensure upload directory exists
const FILES_DIR = path.join(__dirname, 'files');
//const FILES_DIR = '/opt/lampp/htdocs/uploads'; //This is the directory where the uploaded files will be stored in production
fs.mkdirSync(FILES_DIR, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, FILES_DIR),
    filename: (req, file, cb) => {
        const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
        cb(null, safeName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['jpg', 'png', 'txt','php'];
        const ext = file.originalname.split('.').pop().toLowerCase();
        if (!allowed.includes(ext)) {
            return cb(new Error('Invalid file type'));
        }
        cb(null, true);
    }
});

// Serve static files (for html)
app.use(express.static(path.join(__dirname, '../../client/src')));


// Route: Register

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    // Vulnerable bcrypt config: low salt rounds
    const saltRounds = 2;
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        // Insert with default role 'user'
        dbInit.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, 'user'], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ error: 'Username already exists' });
                }
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ message: 'User registered successfully' });
        });
    } catch (e) {
        console.error('Error hashing password:', e);
        res.status(500).json({ error: 'Error hashing password' });
    }
});



// Route: Landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../client/src/landing.html'));
});

// Route: Admin panel
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../../client/src/admin.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../../client/src/register.html'));
});

// Middleware to check JWT token
function authenticateToken(req, res, next) {
    // Support token from Authorization header or from cookies only
    let token = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }
    if (!token) return res.status(401).json({ error: 'No token provided' });
    // Remove 'Bearer ' prefix if present (for cookie)
    if (typeof token === 'string' && token.startsWith('Bearer ')) {
        token = token.slice(7);
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Route: Dashboard (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
    // Try to get token from cookie if not present in Authorization header
    let token = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }
    // If token found, set Authorization header for downstream middleware
    if (token && !authHeader) {
        req.headers['authorization'] = `Bearer ${token}`;
    }
    res.sendFile(path.join(__dirname, '../../client/src/dashboard.html'));
});

// Route: File upload (admin only)
app.post('/upload', authenticateToken, (req, res, next) => {
    // ensure role is admin
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
    next();
}, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'File upload failed' });
    }
    res.json({ message: 'File uploaded successfully', filename: req.file.filename });
});

// Login route: check credentials from DB
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    dbInit.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        // Include role in JWT
        const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        // Prefix token with 'Bearer '
        res.json({ token: `Bearer ${token}` });
    });
});

// Route: Generate CTF flag
app.get('/flag', authenticateToken, (req, res) => {
    const flagText = 'PY{I_GOT_FIRST_ACCESS}';
    res.json({ flag: flagText });
});

// Route: Fetch uploaded files
app.get('/files/:filename', authenticateToken, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(FILES_DIR, filename);
    // Prevent path traversal
    if (!filePath.startsWith(FILES_DIR)) {
        return res.status(400).json({ error: 'Invalid file path' });
    }
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).json({ error: 'File not found' });
        }
        res.sendFile(filePath);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
