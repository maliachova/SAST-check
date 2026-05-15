const fs = require("fs");
const path = require("path");

const helmet = require("helmet");
const express = require("express");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");

const db = require("./database");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Fixed SAST Violation: Added security headers using helmet
app.use(helmet());

// Fixed SAST Violation: Added CSRF protection
const csrfProtection = csrf({ cookie: true });

app.use((_, __, next) => {
	next();
});

const port = process.env.PORT || 3000;

// Fixed SAST Violation: SQL Injection vulnerability - using parameterized query
app.get("/user/:id", (req, res) => {
	const userId = req.params.id;
	const query = "SELECT * FROM users WHERE id = ?";

	db.query(query, [userId], (err, results) => {
		if (err) {
			res.status(500).json({ error: "Internal server error" });
		} else {
			res.json(results);
		}
	});
});

// Fixed SAST Violation: Command injection and Path Traversal - using safer alternatives with strict validation
app.post("/backup", csrfProtection, (req, res) => {
	const filename = req.body.filename;

	// Whitelist validation for filename
	const sanitizedFilename = String(filename).replace(/[^a-zA-Z0-9_-]/g, "");
	if (!sanitizedFilename || sanitizedFilename !== filename) {
		return res.status(400).json({ error: "Invalid filename" });
	}

	// Define backup directory with absolute path
	const backupDir = path.resolve(__dirname, "backups");
	const backupFilename = `${sanitizedFilename}.tar.gz`;
	const backupPath = path.join(backupDir, backupFilename);
    
	// Resolve to get the real absolute path
	const normalizedBackupPath = path.resolve(backupPath);
	const normalizedBackupDir = path.resolve(backupDir);
    
	// Ensure the resolved path is within the backup directory
	if (!normalizedBackupPath.startsWith(normalizedBackupDir + path.sep) && normalizedBackupPath !== normalizedBackupDir) {
		return res.status(403).json({ error: "Access denied" });
	}

	// Verify no path traversal in the final path
	const relativePath = path.relative(normalizedBackupDir, normalizedBackupPath);
	if (relativePath.startsWith("..") || path.isAbsolute(relativePath) || relativePath.includes("..")) {
		return res.status(403).json({ error: "Access denied" });
	}

	// Ensure backups directory exists
	if (!fs.existsSync(normalizedBackupDir)) {
		fs.mkdirSync(normalizedBackupDir, { recursive: true });
	}

	// Use spawn with array arguments to prevent command injection
	const { spawn } = require("child_process");
	const tar = spawn("tar", ["-czf", normalizedBackupPath, "/data/"]);

	tar.on("error", (error) => {
		process.stderr.write(error.stack + "\n");
		return res.status(500).json({ error: "Backup failed" });
	});

	tar.on("close", (code) => {
		if (code === 0) {
			res.json({ message: "Backup created" });
		} else {
			res.status(500).json({ error: "Backup failed" });
		}
	});
});

// Fixed Normal Violation: Using === instead of ==
app.get("/login", (req, res) => {
	const userType = req.query.type;
    
	if (userType === "admin") {
		res.json({ access: "granted" });
	} else {
		res.json({ access: "denied" });
	}
});

// Fixed SAST Violation: XSS vulnerability - using res.render or proper content-type
app.get("/search", (req, res) => {
	const searchTerm = req.query.q;
    
	// Return JSON instead of HTML to avoid XSS
	res.json({ 
		message: "Search results for",
		searchTerm: searchTerm || "",
	});
});

// Fixed SAST Violation: Path traversal - proper validation and sanitization with strict checks
app.get("/file/:filename", (req, res) => {
	const filename = req.params.filename;
    
	// Sanitize filename to prevent path traversal
	const sanitizedFilename = path.basename(filename);
    
	// Validate that the sanitized filename doesn't contain path traversal attempts
	if (sanitizedFilename !== filename || sanitizedFilename.includes("..") || sanitizedFilename.includes(path.sep)) {
		return res.status(400).send("Invalid filename");
	}
    
	// Define uploads directory with absolute path
	const uploadsDir = path.resolve(__dirname, "uploads");
	const filePath = path.join(uploadsDir, sanitizedFilename);
    
	// Resolve to get the real absolute path
	const normalizedPath = path.resolve(filePath);
	const normalizedUploadsDir = path.resolve(uploadsDir);
    
	// Ensure the resolved path is within the uploads directory
	if (!normalizedPath.startsWith(normalizedUploadsDir + path.sep) && normalizedPath !== normalizedUploadsDir) {
		return res.status(403).send("Access denied");
	}

	// Additional check using path.relative to prevent any traversal
	const relativePath = path.relative(normalizedUploadsDir, normalizedPath);
	if (relativePath.startsWith("..") || path.isAbsolute(relativePath) || relativePath.includes("..")) {
		return res.status(403).send("Access denied");
	}
    
	// Verify the file exists and is within the allowed directory before reading
	fs.realpath(normalizedPath, (err, resolvedPath) => {
		if (err) {
			return res.status(404).send("File not found");
		}
        
		// Final check after resolving symlinks
		if (!resolvedPath.startsWith(normalizedUploadsDir + path.sep) && resolvedPath !== normalizedUploadsDir) {
			return res.status(403).send("Access denied");
		}
        
		fs.readFile(resolvedPath, (readErr, data) => {
			if (readErr) {
				res.status(404).send("File not found");
			} else {
				res.send(data);
			}
		});
	});
});

// Fixed Normal Violation: Removed unreachable code
app.listen(port, () => {
	console.log(`Server running on port ${port}`);
});
