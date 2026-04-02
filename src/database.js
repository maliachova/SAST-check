const mysql = require('mysql');

// SAST Violation: Database credentials in code
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password123',  // Hardcoded DB password
    database: 'myapp'
});

// Normal Violation: Callback not using error-first pattern
function getUser(id, callback) {
    const query = 'SELECT * FROM users WHERE id = ?';
    
    connection.query(query, [id], (err, results) => {
        if (err) {
            // Normal Violation: Not following error-first callback pattern
            callback(results, err);  // Parameters in wrong order
        } else {
            callback(results, null);
        }
    });
}

// SAST Violation: NoSQL injection (if using MongoDB-like syntax)
function findUserByEmail(email) {
    // Assuming this would be vulnerable in NoSQL context
    const query = { email: email };
    return query;
}

// Normal Violation: Inconsistent naming convention
function Get_All_Users() {  // Should be camelCase
    return new Promise((resolve, reject) => {
        connection.query('SELECT * FROM users', (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}

// SAST Violation: Sensitive data logging
function logDatabaseQuery(query, params) {
    console.log('Executing query:', query);
    console.log('With parameters:', params);  // May log sensitive data
}

module.exports = {
    connection,
    getUser,
    findUserByEmail,
    Get_All_Users,
    logDatabaseQuery
};