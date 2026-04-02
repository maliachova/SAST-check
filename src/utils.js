// Normal Violation: Missing 'use strict'
// 'use strict'; is missing

const fs = require('fs');

// Normal Violation: Using == instead of ===
function isEmpty(value) {
    return value == null || value == '';  // Should use ===
}

// SAST Violation: eval() usage
function executeCode(userCode) {
    // Extremely dangerous - arbitrary code execution
    return eval(userCode);
}

// Normal Violation: Function parameter reassignment
function processData(data) {
    data = data || {};  // Parameter reassignment
    data.processed = true;
    return data;
}

// SAST Violation: File operation without proper validation
function readConfigFile(filename) {
    try {
        // No path validation - potential security issue
        const content = fs.readFileSync(filename, 'utf8');
        return JSON.parse(content);
    } catch (e) {
        // SAST Violation: Generic catch block
        return null;
    }
}

// Normal Violation: Magic numbers
function calculateDiscount(price) {
    if (price > 100) {
        return price * 0.1;  // Magic number 0.1
    }
    return price * 0.05;  // Magic number 0.05
}

// SAST Violation: Regular expression DoS (ReDoS)
function validateEmail(email) {
    const regex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    // This regex could be vulnerable to ReDoS with crafted input
    return regex.test(email);
}

// Normal Violation: No default case in switch
function getStatusMessage(code) {
    switch (code) {
        case 200:
            return 'OK';
        case 404:
            return 'Not Found';
        case 500:
            return 'Server Error';
        // Missing default case
    }
}

// SAST Violation: Prototype pollution vulnerability
function merge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];  // No protection against __proto__
        }
    }
    return target;
}

module.exports = {
    isEmpty,
    executeCode,
    processData,
    readConfigFile,
    calculateDiscount,
    validateEmail,
    getStatusMessage,
    merge
};