const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');  

const app = express();

require('dotenv').config();

const PORT = process.env.PORT || 3000;







const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,

    ssl: {
        rejectUnauthorized: false,
    }, //dodano ovo za deploy
});


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: true,

    name: 'customSessionID',  
    cookie: {
        httpOnly: true,  // Kolačić dostupan samo putem HTTP(S), ne putem JavaScript-a
        secure: process.env.NODE_ENV === 'production',  // Koristi HTTPS samo u produkciji, inače kolačić se šalje samo putem HTTPS-a
        sameSite: 'strict',  // Sprečava slanje kolačića u cross-site zahtjevima
        maxAge: 600000  // Trajanje kolačića (ovdje je postavljeno na 600 sekundi)
    },
    genid: (req) => {
        // Koristi crypto modul za generiranje nasumičnog session ID-a
        return crypto.randomBytes(16).toString('hex');  // nasumični session ID
    }

}));





app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');






app.get('/', (req, res) => {
    res.redirect('/login'); 
});




app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});













function sanitizeInput(input) {
    return input.replace(/['"]/g, ''); // Uklanja jednostruke i dvostruke navodnike
}

app.post('/login', async (req, res) => {
    let { username, password } = req.body;

    username = sanitizeInput(username);
    password = sanitizeInput(password);

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                req.session.userId = user.id;
                res.redirect('/home');
            } else {
                res.send('Incorrect credentials. Try again.');
            }
        } else {
            res.send('Incorrect credentials. Try again.');
        }
    } catch (err) {
        console.error(err);
        res.send('Error occurred during login');
    }
});




app.get('/home', (req, res) => {
    if (!req.session.userId) {
        res.redirect('/login'); 
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});









app.get('/sql-injection', (req, res) => {
    if (!req.session.userId) {
        res.redirect('/login');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'sql-injection.html'));
    }
});




app.post('/execute-sql-injection', async (req, res) => {
    const { query, enable } = req.body; 
    let result = { rows: [] }; 
    let message = '';

    try {
        if (enable === 'on') {
            
            // Ulančani upiti (stacked queries) - PostgreSQL ne podržava višestruke upite u jednom pozivu query()!
            if (query.includes(";")) {
                // Podijeli upit na dva dijela po prvom ; (točka-zarez)
                const parts = query.split(";");

                // Ako postoji bilo što nakon prvog ; to znači da je višestruki upit
                if (parts.length > 1 && parts[1].trim() !== "") {
                    message = 'Detected stacked queries (multiple statements). This is not allowed.';
                } else {
                    // Ako nema ništa nakon ; znači da je samo jedan upit
                    // SQL Injection napadi
                    if (query.toLowerCase().includes("1=1")) {
                        // Tautologija - ovaj upit će uvijek vratiti istinit rezultat
                        result = await pool.query(`SELECT * FROM users WHERE username = 'admin' OR 1=1`);
                        message = 'Executed tautology query (1=1)';
                    }
                    // Ilegalni upiti prema informacijama o bazi (pristup shemi baze)
                    else if (query.toLowerCase().includes("information_schema")) {
                        result = await pool.query(query); // Pokušaj doznati strukturu baze
                        message = 'Executed illegal query to get DB schema';
                    }
                    // Injekcija na slijepo
                    else if (query.toLowerCase().includes("true") || query.toLowerCase().includes("false")) {
                        // Osiguravamo da `query` sadrži ispravan dio za WHERE klauzulu
                        const condition = query.toLowerCase().includes("true") ? "true" : "false";
                        result = await pool.query(`SELECT * FROM users WHERE ${condition}`);
                        message = 'Executed blind SQL injection query';
                    }
                    // UNION napad
                    else if (query.toLowerCase().includes("union")) {
                        result = await pool.query(query); // UNION attack
                        message = 'Executed UNION query';
                    } else {
                        result = await pool.query(query); // Generalni SQL Injection
                        message = 'Executed general SQL query';
                    }
                }
            }
            // Default - ako nijedan napad nije prepoznat
            else {
                result = await pool.query(query); // Generalni SQL Injection
                message = 'Executed general SQL query';
            }
            
        } else {
            // Sigurna verzija sa parametriziranim upitom
            const { userId } = req.body;
            result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
            message = 'Executed secure query';
        }

        // Slanje rezultata natrag
        res.json({ message, data: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error executing query');
    }
});






app.get('/broken-auth', (req, res) => {
    if (!req.session.userId) {
        res.redirect('/login');
    } else {
        res.render('broken-auth', {
            captchaSiteKey: process.env.RECAPTCHA_SITEKEY 
        });
    }
});







app.post('/simulate-broken-auth', async (req, res) => {
    let { username, password, vulnerabilityEnabled, 'g-recaptcha-response': captchaResponse } = req.body;

    // Ako nema sesije za pokušaje, postavi na 0
    if (!req.session.attempts) {
        req.session.attempts = 0;
    }
    
    // Ako je korisnik zaključan i ranjivost nije uključena, provjeri je li prošlo 1 minuta
    if (vulnerabilityEnabled === 'false' && req.session.lockUntil && req.session.lockUntil > Date.now()) {
        const remainingLockTime = Math.ceil((req.session.lockUntil - Date.now()) / 1000);
        return res.send(`Račun je zaključan. Pokušajte ponovno za ${remainingLockTime} sekundi.`);
    }

    // Sanitizacija unosa
    username = sanitizeInput(username);
    password = sanitizeInput(password);


    const captchaSecret = process.env.RECAPTCHA_SECRET;
    const captchaVerifyUrl = `https://www.google.com/recaptcha/api/siteverify`;

    try {
        // Provjera CAPTCHA samo ako je ranjivost isključena
        if (vulnerabilityEnabled === 'false') {
            const captchaVerification = await axios.post(captchaVerifyUrl, null, {
                params: {
                    secret: captchaSecret,
                    response: captchaResponse,
                }
            });

            if (!captchaVerification.data.success) {
                console.error('CAPTCHA greška:', captchaVerification.data['error-codes']);
                return res.send('CAPTCHA verifikacija neuspješna. Pokušajte ponovno.');
            }
        }

        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                req.session.attempts = 0; // Resetiraj pokušaje ako je prijava uspješna
                req.session.userId = user.id;
                return res.send(vulnerabilityEnabled === 'true' ? 'Prijava uspješna (ranjiva)!' : 'Prijava uspješna!');
            } else {
                if (vulnerabilityEnabled === 'false') {
                    // Ako je ranjivost isključena, brojimo neuspješne pokušaje i zaključavamo nakon 3 pokušaja
                    req.session.attempts += 1;

                    if (req.session.attempts >= 3) {
                        req.session.lockUntil = Date.now() + 60000; // Zaključaj račun na 60 sekundi
                        req.session.attempts = 0; // Resetiraj broj pokušaja nakon zaključavanja
                        return res.send('Previše neuspjelih pokušaja. Račun zaključan na 1 minutu.');
                    }

                    const remainingAttempts = 3 - req.session.attempts;
                    return res.send(`Neuspješna prijava. Preostalo pokušaja: ${remainingAttempts}.`);
                } else {
                    // Ako je ranjivost uključena, ne brojimo pokušaje
                    return res.send('Neuspješna prijava (ranjiva).');
                }
            }
        } else {
            if (vulnerabilityEnabled === 'false') {
                // Ako je ranjivost isključena, brojimo neuspješne pokušaje i zaključavamo nakon 3 pokušaja
                req.session.attempts += 1;
                
                if (req.session.attempts >= 3) {
                    req.session.lockUntil = Date.now() + 60000;
                    req.session.attempts = 0;
                    return res.send('Previše neuspjelih pokušaja. Račun zaključan na 1 minutu.');
                }

                const remainingAttempts = 3 - req.session.attempts;
                return res.send(`Neuspješna prijava. Preostalo pokušaja: ${remainingAttempts}.`);
            } else {
                // Ako je ranjivost uključena, ne brojimo pokušaje
                return res.send('Neuspješna prijava (ranjiva).');
            }
        }

    } catch (error) {
        console.error('Greška tijekom CAPTCHA provjere:', error.message);
        res.send('Došlo je do greške prilikom CAPTCHA provjere. Pokušajte ponovno.');
    }
});




















app.get('/session-status', (req, res) => {
    res.json({ loggedIn: !!req.session.userId }); 
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        res.redirect('/'); 
    });
});






app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});




