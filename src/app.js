const express = require('express');
const auth = require('./auth');
const db = require('./database');
const utils = require('./utils');

const a = 30;

const app = express();
app.use(express.json());

// SAST Violation: Missing security headers
app.use((req, res, next) => {
    // Missing security headers like helmet
    next();
});

// Normal Violation: Unused variable
var unusedVariable = "This is never used";

// Normal Violation: Missing semicolon and wrong quotes
const port = process.env.PORT || 3000

// SAST Violation: Hardcoded secret
const SECRET_KEY = "hardcoded-secret-key-12345";

// SAST Violation: SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Direct string concatenation - SQL injection risk
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    db.query(query, (err, results) => {
        if (err) {
            // SAST Violation: Information disclosure
            res.status(500).json({ error: err.message, stack: err.stack });
        } else {
            res.json(results);
        }
    });
});

// SAST Violation: Command injection
app.post('/backup', (req, res) => {
    const filename = req.body.filename;
    const exec = require('child_process').exec;
    
    // Command injection vulnerability
    exec(`tar -czf ${filename}.tar.gz /data/`, (error, stdout, stderr) => {
        if (error) {
            console.error(error);
            return;
        }
        res.json({ message: 'Backup created' });
    });
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
    const html = `<h1>Search results for: ${searchTerm}</h1>`; // XSS vulnerability
    res.send(html);
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
