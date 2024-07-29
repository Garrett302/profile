const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

let db;

(async () => {
    db = await mysql.createConnection({
        host: 'localhost',
        user: 'your-username',
        password: 'your-password',
        database: 'your-database'
    });

    await db.query(`
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            bio TEXT,
            profile_picture_url VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `);
})();

passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
            if (!rows.length) {
                return done(null, false, { message: 'Incorrect username.' });
            }

            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Incorrect password.' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
        done(null, rows[0]);
    } catch (err) {
        done(err, null);
    }
});

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Unauthorized' });
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

app.post('/api/profile', isAuthenticated, upload.single('profile_picture'), async (req, res) => {
    const { bio } = req.body;
    const profile_picture_url = req.file ? `/uploads/${req.file.filename}` : null;
    const user_id = req.user.id;

    try {
        const [rows] = await db.query('SELECT id FROM user_profiles WHERE user_id = ?', [user_id]);
        if (rows.length) {
            await db.query('UPDATE user_profiles SET bio = ?, profile_picture_url = ? WHERE user_id = ?', [bio, profile_picture_url, user_id]);
        } else {
            await db.query('INSERT INTO user_profiles (user_id, bio, profile_picture_url) VALUES (?, ?, ?)', [user_id, bio, profile_picture_url]);
        }

        res.status(201).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/api/profile', isAuthenticated, async (req, res) => {
    const user_id = req.user.id;

    try {
        const [profileRows] = await db.query('SELECT * FROM user_profiles WHERE user_id = ?', [user_id]);
        if (!profileRows.length) {
            return res.status(404).json({ message: 'Profile not found' });
        }

        const profile = profileRows[0];
        res.status(200).json(profile);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));



const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
