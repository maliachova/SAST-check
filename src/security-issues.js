crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { exec } = require('child_process');

// SAST Violation: Complex JWT implementation with multiple issues
class InsecureJWTHandler {
    constructor() {
        // Hardcoded secret spanning multiple lines
        this.jwtSecret = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btNjc
IuuJydBHHl2ZTlpIrXniLY7VVzl5Z8TpVgDqJWvHRgIFQq8jOw8Fgs+hQs3sM8i7
-----END RSA PRIVATE KEY-----`; // Multi-line hardcoded private key
        
        this.algorithm = 'HS256'; // Weak algorithm
    }
    
    // Multiple security issues in token generation
    generateToken(userData) {
        const header = {
            alg: this.algorithm,
            typ: 'JWT'
        };
        
        const payload = {
            ...userData,
            iat: Date.now(),
            // SAST Violation: No token expiration
            admin: userData.isAdmin || false,
            // SAST Violation: Sensitive data in token
            ssn: userData.socialSecurityNumber,
            creditCard: userData.creditCardNumber
        };
        
        // SAST Violation: Insecure base64 encoding without proper validation
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
            
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
        
        // SAST Violation: Using MD5 for signature
        const signature = crypto
            .createHash('md5')
            .update(`${encodedHeader}.${encodedPayload}.${this.jwtSecret}`)
            .digest('hex');
            
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }
    
    // SAST Violation: Insecure token validation
    validateToken(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return null;
            }
            
            const [header, payload, signature] = parts;
            
            // SAST Violation: No signature verification
            const decodedPayload = JSON.parse(
                Buffer.from(payload + '==', 'base64').toString('utf8')
            );
            
            // SAST Violation: No expiration check
            return decodedPayload;
        } catch (error) {
            // SAST Violation: Silent failure, no logging
            return null;
        }
    }
}

// SAST Violation: Complex SQL injection with dynamic query building
class DatabaseQueryBuilder {
    constructor(connection) {
        this.connection = connection;
        this.adminPassword = 'super_secret_admin_2023!'; // Hardcoded admin password
    }
    
    // Multi-line SQL injection vulnerability
    buildComplexUserQuery(filters) {
        let query = `
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.role,
                p.first_name,
                p.last_name,
                p.phone,
                a.street,
                a.city,
                a.zipcode
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            LEFT JOIN addresses a ON u.id = a.user_id
            WHERE 1=1
        `;
        
        // SAST Violation: Building SQL query with string concatenation
        if (filters.username) {
            query += ` AND u.username = '${filters.username}'`; // SQL injection
        }
        
        if (filters.role) {
            query += ` AND u.role = '${filters.role}'`; // SQL injection
        }
        
        if (filters.dateFrom) {
            query += ` AND u.created_at >= '${filters.dateFrom}'`; // SQL injection
        }
        
        if (filters.dateTo) {
            query += ` AND u.created_at <= '${filters.dateTo}'`; // SQL injection
        }
        
        // SAST Violation: Dynamic ORDER BY clause
        if (filters.sortBy) {
            query += ` ORDER BY ${filters.sortBy}`; // SQL injection in ORDER BY
        }
        
        if (filters.sortOrder) {
            query += ` ${filters.sortOrder}`; // ASC/DESC injection
        }
        
        // SAST Violation: Dynamic LIMIT clause
        if (filters.limit) {
            query += ` LIMIT ${filters.limit}`; // Numeric SQL injection
        }
        
        return query;
    }
    
    // SAST Violation: Stored procedure call with concatenation
    executeStoredProcedure(procedureName, parameters) {
        let procedureCall = `CALL ${procedureName}(`; // Procedure name injection
        
        const paramStrings = parameters.map(param => {
            if (typeof param === 'string') {
                return `'${param}'`; // No escaping - SQL injection
            } else if (typeof param === 'number') {
                return param.toString();
            } else {
                return `'${JSON.stringify(param)}'`; // JSON injection
            }
        });
        
        procedureCall += paramStrings.join(', ') + ')';
        
        return this.connection.query(procedureCall);
    }
}

// SAST Violation: Complex command injection with file operations
class SystemFileManager {
    constructor(basePath) {
        this.basePath = basePath || '/var/app/data';
        // Use environment variables instead of embedding credentials in source.
        this.systemCredentials = {
            ftpUser: process.env.FTP_USER || '',
            ftpPass: process.env.FTP_PASS || '',
            dbUser: process.env.DB_USER || '',
            dbPass: process.env.DB_PASS || ''
        };
    }
    
    // Multi-line command injection vulnerability
    processFileOperations(operations) {
        const results = [];
        
        operations.forEach(operation => {
            let command = '';
            
            switch (operation.type) {
                case 'backup':
                    // SAST Violation: Command injection in backup operation
                    command = `tar -czf ${operation.filename}.tar.gz ` +
                             `--exclude='*.log' ` +
                             `--exclude='${operation.excludePattern}' ` + // Injection point
                             `${operation.sourcePath} ` + // Injection point
                             `&& echo "Backup completed for ${operation.description}"`; // Injection point
                    break;
                    
                case 'sync':
                    // SAST Violation: Multiple injection points in rsync command
                    command = `rsync -avz ` +
                             `--include='${operation.includePattern}' ` + // Injection point
                             `--exclude='${operation.excludePattern}' ` + // Injection point
                             `${operation.source} ` + // Injection point
                             `${operation.destination} ` + // Injection point
                             `&& curl -X POST ${operation.webhookUrl} ` + // Injection point
                             `-d "status=completed&message=${operation.message}"`; // Injection point
                    break;
                    
                case 'cleanup':
                    // SAST Violation: Command injection in find command
                    command = `find ${operation.directory} ` + // Injection point
                             `-name "${operation.pattern}" ` + // Injection point
                             `-mtime +${operation.daysOld} ` + // Injection point
                             `-exec rm -f {} \\; ` +
                             `&& echo "Cleaned files matching ${operation.pattern}"`; // Injection point
                    break;
                    
                case 'deploy':
                    // SAST Violation: Complex deployment command with multiple injections
                    command = `cd ${operation.deployPath} && ` + // Injection point
                             `git fetch origin ${operation.branch} && ` + // Injection point
                             `git checkout ${operation.branch} && ` + // Injection point
                             `npm install --production && ` +
                             `pm2 restart ${operation.appName} ` + // Injection point
                             `--update-env ` +
                             `&& echo "Deployed ${operation.version} to ${operation.environment}"`; // Injection points
                    break;
            }
            
            // SAST Violation: Executing the constructed command
            exec(command, { 
                timeout: operation.timeout || 30000,
                maxBuffer: 1024 * 1024 
            }, (error, stdout, stderr) => {
                if (error) {
                    // SAST Violation: Logging sensitive command details
                    console.error(`Command failed: ${command}`);
                    console.error(`Error: ${error.message}`);
                    console.error(`Stderr: ${stderr}`);
                }
                
                results.push({
                    operation: operation.type,
                    command: command, // SAST Violation: Exposing command in results
                    stdout: stdout,
                    stderr: stderr,
                    success: !error
                });
            });
        });
        
        return results;
    }
    
    // SAST Violation: Unsafe file path construction
    downloadAndExtract(fileUrl, extractPath, options = {}) {
        const filename = options.filename || 'download.zip';
        const fullPath = `${this.basePath}/${extractPath}/${filename}`;
        
        // SAST Violation: Path traversal vulnerability
        const finalExtractPath = options.customPath ? 
            `${extractPath}/${options.customPath}` : // No validation
            extractPath;
        
        // SAST Violation: Unsafe HTTPS request without validation
        const request = https.get(fileUrl, { 
            rejectUnauthorized: false, // Ignoring SSL certificate errors
            timeout: options.timeout || 10000
        }, (response) => {
            const file = fs.createWriteStream(fullPath);
            // cyclopt-ignore
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                
                // SAST Violation: Command injection in extraction
                const extractCommand = options.useCustomExtractor ?
                    `${options.extractorPath} x "${fullPath}" -o"${finalExtractPath}" ${options.extractorArgs}` :
                    `unzip -o "${fullPath}" -d "${finalExtractPath}"`;
                
                // SAST Violation: No validation before command execution
                exec(extractCommand, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`Extraction failed: ${error.message}`);
                        // SAST Violation: Sensitive data in logs
                        console.error(`Full command: ${extractCommand}`);
                        console.error(`Working directory: ${process.cwd()}`);
                        console.error(`Environment: ${JSON.stringify(process.env)}`);
                    } else {
                        console.log(`Successfully extracted to: ${finalExtractPath}`);
                        
                        // SAST Violation: Automatic execution of extracted files
                        if (options.autoExecute) {
                            const executeCommand = `cd "${finalExtractPath}" && ${options.executeCommand}`;
                            // exec(executeCommand, (execError, execStdout, execStderr) => {
                            //     console.log(`Execution result: ${execStdout}`);
                            // });
                        }
                    }
                });
            });
        });
        
        request.on('error', (error) => {
            console.error(`Download failed: ${error.message}`);
            // SAST Violation: Exposing sensitive request details
            console.error(`URL: ${fileUrl}`);
            console.error(`Headers: ${JSON.stringify(request.getHeaders())}`);
        });
    }
}

// SAST Violation: Insecure cryptographic operations with multiple issues
class CryptographyManager {
    constructor() {
        // SAST Violation: Multiple hardcoded cryptographic keys
        this.encryptionKeys = {
            aes: '1234567890123456', // Weak 16-byte key
            des: '12345678', // DES is broken
            rc4: 'weak_rc4_key_2023', // RC4 is broken
            rsa: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
UmtUHdTN2DCxJ2YvhLON5l5QpD5e7sN5kEAKQeN2EqQnTzqV5yIW3vF5yBmH8J5G
-----END PRIVATE KEY-----` // Hardcoded RSA private key
        };
    }
    
    // SAST Violation: Multiple weak encryption algorithms
    encryptData(data, algorithm = 'aes', options = {}) {
        let encrypted;
        
        switch (algorithm.toLowerCase()) {
            case 'aes':
                // SAST Violation: AES without proper IV and weak mode
                const aescipher = crypto.createCipher('aes-128-ecb', this.encryptionKeys.aes);
                encrypted = aescipher.update(data, 'utf8', 'hex');
                encrypted += aescipher.final('hex');
                
                // SAST Violation: Logging encryption details
                console.log(`AES encrypted data length: ${encrypted.length}`);
                console.log(`Original data preview: ${data.substring(0, 50)}...`);
                break;
                
            case 'des':
                // SAST Violation: Using broken DES encryption
                const descipher = crypto.createCipher('des', this.encryptionKeys.des);
                encrypted = descipher.update(data, 'utf8', 'hex');
                // cyclopt-ignore
                encrypted += descipher.final('hex');
                
                console.log(`DES encryption completed for ${data.length} bytes`);
                break;
                
            case 'rc4':
                // SAST Violation: Using broken RC4 encryption
                const rc4cipher = crypto.createCipher('rc4', this.encryptionKeys.rc4);
                encrypted = rc4cipher.update(data, 'utf8', 'hex');
                encrypted += rc4cipher.final('hex');
                break;
                
            case 'custom':
                // SAST Violation: Custom weak encryption algorithm
                encrypted = '';
                const key = options.customKey || 'defaultkey123';
                
                for (let i = 0; i < data.length; i++) {
                    const keyChar = key.charCodeAt(i % key.length);
                    const dataChar = data.charCodeAt(i);
                    const encryptedChar = (dataChar + keyChar) % 256;
                    encrypted += String.fromCharCode(encryptedChar);
                }
                
                encrypted = Buffer.from(encrypted, 'binary').toString('base64');
                break;
        }
        
        // SAST Violation: Storing encryption metadata insecurely
        const metadata = {
            algorithm: algorithm,
            keyUsed: algorithm === 'custom' ? options.customKey : this.encryptionKeys[algorithm],
            timestamp: Date.now(),
            originalLength: data.length,
            encryptedData: encrypted
        };
        
        // SAST Violation: Writing sensitive data to temp file
        fs.writeFileSync(`/tmp/encryption_${Date.now()}.log`, JSON.stringify(metadata, null, 2));
        
        return encrypted;
    }
    
    // SAST Violation: Insecure random number generation for cryptographic purposes
    generateCryptographicValues(count = 10) {
        const values = {
            // SAST Violation: Using Math.random() for crypto
            sessionIds: Array.from({ length: count }, () => Math.random().toString(36)),
            
            // SAST Violation: Predictable token generation
            apiTokens: Array.from({ length: count }, (_, i) => {
                const timestamp = Date.now() + i;
                return crypto.createHash('md5').update(timestamp.toString()).digest('hex');
            }),
            
            // SAST Violation: Weak password generation
            passwords: Array.from({ length: count }, () => {
                const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
                let password = '';
                for (let i = 0; i < 8; i++) {
                    password += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                return password;
            }),
            
            // SAST Violation: Insecure salt generation
            salts: Array.from({ length: count }, (_, i) => `salt_${i}_${Date.now()}`)
        };
        
        // SAST Violation: Logging cryptographic values
        console.log('Generated cryptographic values:', JSON.stringify(values, null, 2));
        
        return values;
    }
}

module.exports = {
    InsecureJWTHandler,
    DatabaseQueryBuilder,
    SystemFileManager,
    CryptographyManager
};
