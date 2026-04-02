const bcrypt = require('bcrypt');

// Normal Violation: Missing semicolon
const crypto = require('crypto')

// SAST Violation: Weak cryptographic algorithm
function generateToken() {
    // MD5 is cryptographically broken
    return crypto.createHash('md5').update(Date.now().toString()).digest('hex');
}

// SAST Violation: Hardcoded credentials
const DEFAULT_ADMIN = {
    username: 'admin',
    password: 'admin123',  // Hardcoded password
    apiKey: 'sk-1234567890abcdef'  // Hardcoded API key
};

// Normal Violation: Inconsistent return statements
function validateUser(username, password) {
    if (!username) {
        return false;
    }
    
    if (!password) {
        return;  // Inconsistent return type
    }
    
    // SAST Violation: Timing attack vulnerability
    if (username === DEFAULT_ADMIN.username && password === DEFAULT_ADMIN.password) {
        return true;
    }
    
    return false;
}

// SAST Violation: Insufficient password complexity
function isPasswordValid(password) {
    return password.length >= 3;  // Too weak requirement
}

// Normal Violation: Using var instead of const/let
var sessionTimeout = 3600;

// SAST Violation: Insecure random number generation
function generateSessionId() {
    return Math.random().toString(36);  // Not cryptographically secure
}

// Normal Violation: Missing error handling
function hashPassword(password) {
    // No try-catch or error handling
    return bcrypt.hashSync(password, 10);
}

module.exports = {
    generateToken,
    validateUser,
    isPasswordValid,
    generateSessionId,
    hashPassword
};