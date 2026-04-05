# SAST Violations Report

Total SAST violations found: 67

## src/security-issues.js (47)
1. Line 6: Complex JWT implementation with multiple issues
2. Line 28: No token expiration
3. Line 30: Sensitive data in token
4. Line 35: Insecure base64 encoding without proper validation
5. Line 46: Using MD5 for signature
6. Line 55: Insecure token validation
7. Line 65: No signature verification
8. Line 70: No expiration check
9. Line 73: Silent failure, no logging
10. Line 79: Complex SQL injection with dynamic query building
11. Line 106: Building SQL query with string concatenation
12. Line 123: Dynamic ORDER BY clause
13. Line 132: Dynamic LIMIT clause
14. Line 140: Stored procedure call with concatenation
15. Line 160: Complex command injection with file operations
16. Line 164: Hardcoded system credentials
17. Line 182: Command injection in backup operation
18. Line 191: Multiple injection points in rsync command
19. Line 202: Command injection in find command
20. Line 211: Complex deployment command with multiple injections
21. Line 222: Executing the constructed command
22. Line 228: Logging sensitive command details
23. Line 236: Exposing command in results
24. Line 247: Unsafe file path construction
25. Line 252: Path traversal vulnerability
26. Line 257: Unsafe HTTPS request without validation
27. Line 269: Command injection in extraction
28. Line 274: No validation before command execution
29. Line 278: Sensitive data in logs
30. Line 285: Automatic execution of extracted files
31. Line 299: Exposing sensitive request details
32. Line 306: Insecure cryptographic operations with multiple issues
33. Line 309: Multiple hardcoded cryptographic keys
34. Line 321: Multiple weak encryption algorithms
35. Line 327: AES without proper IV and weak mode
36. Line 332: Logging encryption details
37. Line 338: Using broken DES encryption
38. Line 347: Using broken RC4 encryption
39. Line 354: Custom weak encryption algorithm
40. Line 369: Storing encryption metadata insecurely
41. Line 378: Writing sensitive data to temp file
42. Line 384: Insecure random number generation for cryptographic purposes
43. Line 387: Using Math.random() for crypto
44. Line 390: Predictable token generation
45. Line 396: Weak password generation
46. Line 406: Insecure salt generation
47. Line 410: Logging cryptographic values

## src/database.js (3)
1. Line 3: Database credentials in code
2. Line 25: NoSQL injection (if using MongoDB-like syntax)
3. Line 45: Sensitive data logging

## src/auth.js (5)
1. Line 6: Weak cryptographic algorithm
2. Line 12: Hardcoded credentials
3. Line 29: Timing attack vulnerability
4. Line 37: Insufficient password complexity
5. Line 45: Insecure random number generation

## src/app.js (7)
1. Line 11: Missing security headers
2. Line 23: Hardcoded secret
3. Line 26: SQL Injection vulnerability
4. Line 34: Information disclosure
5. Line 42: Command injection
6. Line 71: XSS vulnerability and Normal Violation: Using var instead of const/let
7. Line 77: Path traversal

## src/utils.js (5)
1. Line 11: eval() usage
2. Line 24: File operation without proper validation
3. Line 31: Generic catch block
4. Line 44: Regular expression DoS (ReDoS)
5. Line 64: Prototype pollution vulnerability
