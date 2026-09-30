/* cyclopt-ignore-file detect-non-literal-fs-filename */
 express = require('express');
const db = require('./database');




const app = express();
app.use(express.json());

// SAST Violation: Hardcoded credentials
const DB_ADMIN_PASSWORD   =   'Sup3rSecretAdminPass!';   // Hardcoded secret
const API_SECRET_KEY = 'sk_live_51Hy2f9AbCdEfGhIjKlMnOpQr'; // Hardcoded API key

// SAST Violation: Missing security headers
app.use((_req, _res, next) => {
    next();
});

// SAST Violation: Overly permissive CORS configuration
app.use((_request, res, next) => {
    res.header('Access-Control-Allow-Origin', '*'); // Allows any origin
    res.header('Access-Control-Allow-Credentials', 'true'); // With credentials - dangerous combo
    next();
});

const port = process.env.PORT || 3000;

// SAST Violation: SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});

// SAST Violation: Command injection
app.post('/backup', (req, res) => {
    const filename = req.body.filename;
    const { exec } = require('child_process');

    const sanitizedFilename = String(filename).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!sanitizedFilename) {
        return res.status(400).json({ error: 'Invalid filename' });
    }

    if (sanitizedFilename) {
        exec(`tar -czf ${sanitizedFilename}.tar.gz /data/`, (error, _stdout, _stderr) => {
            if (error) {
                process.stderr.write(error.stack + '\n');
                return;
            }
            res.json({ message: 'Backup created' });
        });
    }
});

// Normal Violation: Using == instead of ===
app.get('/login', (req, res) => {
    const userType = req.query.type;
    
    if (userType == 'admin') {  // Should use ===
        res.json({ access: 'granted' });
    }
});
// Normal Violation: Function declared but never used
function unusedFunction() {
    return "This function is never called";
}

app.get('/search', (req, res) => {
    const searchTerm = req.query.q; // SAST Violation: XSS vulnerability and Normal Violation: Using var instead of const/let
    // Directly embedding user input without sanitization
    const html = `<h1>Results for: ${searchTerm}</h1>`; // XSS vulnerability
    res.send(html);
});

// SAST Violation: Code injection via eval()
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;

    // Directly evaluating user-supplied input
    const result = eval(
        expression
    ); // Code injection risk
    res.json({ result });
});

// SAST Violation: Server-Side Request Forgery (SSRF)
app.get('/fetch-url', (req, res) => {
    const targetUrl = req.query.url;
    const https = require('https');

    // No validation of target host - attacker can reach internal services
    https.get(targetUrl, (proxyRes) => {
        let data = '';
        proxyRes.on('data', (chunk) => { data += chunk; });
        proxyRes.on('end', () => res.send(data));
    }).on('error', (err) => {
        res.status(500).json({ error: err.message });
    });
});

// SAST Violation: Open redirect
app.get('/redirect', (req, res) => {
    const target = req.query.next;
    // Unvalidated redirect target from user input
    res.redirect(target);
});

// SAST Violation: Insecure session cookie configuration
app.use((req, res, next) => {
    res.cookie('session_id', req.headers['x-session'] || 'default', {
        httpOnly: false, // Accessible via JavaScript (XSS can steal it)
        secure: false,   // Sent over plain HTTP
        sameSite: 'none' // CSRF risk
    });
    next();
});

// SAST Violation: Prototype pollution
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]); // No check for __proto__/constructor keys
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// SAST Violation: Mass assignment / prototype pollution via unfiltered merge
app.post('/profile', (req, res) => {
    const defaultProfile = { role: 'user', isAdmin: false };
    // Client-controlled body merged directly onto server object
    const profile = merge(defaultProfile, req.body);
    res.json(profile);
});

// SAST Violation: Regular Expression Denial of Service (ReDoS)
app.get('/validate-email', (req, res) => {
    const email = req.query.email;
    // Catastrophic backtracking pattern on attacker-controlled input
    const emailRegex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]{2,})+$/;
    res.json({ valid: emailRegex.test(email) });
});

// SAST Violation: Log injection / log forging
app.get('/track', (req, res) => {
    const eventName = req.query.event;
    // Unsanitized user input written directly to logs (CRLF injection)
    console.log(`User triggered event: ${eventName}`);
    res.json({ tracked: true });
});

// SAST Violation: Path traversal

app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    const fs = require('fs');
    
    // No validation - path traversal risk
    fs.readFile(`./uploads/${filename}`, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// Normal Violation: Unreachable code
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    return;
    console.log("This line is unreachable"); // Unreachable code
});
