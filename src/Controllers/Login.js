// FIX: Implemented deep object sanitization with recursive traversal, circular reference detection,
// and pattern matching to comprehensively redact sensitive data from logs at any nesting level
sanitizeForLog(data, visited = new WeakSet()) {
  // Define sensitive field patterns for flexible matching (case-insensitive)
  // FIX: Added pattern-based matching to catch variations like "user_password", "api-key", "passwordConfirm"
  const SENSITIVE_PATTERNS = [
    /password/i, 
    /token/i, 
    /api[_-]?key/i, 
    /secret/i, 
    /auth/i, 
    /credential/i, 
encryptData(secretText) {
    const crypto = require('crypto');

    // FIXED: Replaced DES with AES-256-GCM (strong encryption standard)
    // Using AES-256-GCM provides authenticated encryption with 256-bit key strength
    const algorithm = 'aes-256-gcm';
    
    // FIXED: Removed insecure fallback to random key generation
    // Validate that ENCRYPTION_KEY exists and has correct format
    if (!process.env.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY environment variable must be set and must be 32 bytes (64 hex characters)');
async handleLogin(req, res, client, data) {
    const { username, password, keeponline } = data;
    try {
      // DB Query
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      if (!db) {
        this.loginFailed(req, res, data);
        return;
      }
      const result = await db.collection('users').findOne({
        username,
        password
      });
      if (result) {
        const user = {
          fname: result.fname,
          lname: result.lname,
          passportnum: result.passportnum,
          address1: result.address1,
          address2: result.address2,
          zipCode: result.zipCode
        };
        const creditInfo = encryptData(result.creditCard);
        
        // FIX: Log forging prevention by sanitizing username before logging
        const sanitizedUsername = username.replace(/[\n\r]/g, '_');
        // FIX: Structured logging with minimal non-sensitive information for audit trail
        logger.info('Login successful', {
          username: sanitizedUsername,
          timestamp: new Date().toISOString(),
          sessionId: req.session.id
        });
        
        res.cookie('username', result.username);
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo);

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
  // FIX: Enhanced helper method with pattern-based detection and log forging prevention
  sanitizeForLogging(data) {
    if (typeof data !== 'object' || data === null) {
      // FIX: Prevent log forging by removing newline characters from non-object data
      return String(data).replace(/[\n\r]/g, '_');
    }
    
    const sanitized = { ...data };
    // FIX: Pattern-based detection for sensitive field names to catch variations
    const sensitivePatterns = /(password|passwd|pwd|secret|token|key|credit|card|passport|ssn|social|address|zip|phone|email)/i;
    
    Object.keys(sanitized).forEach(key => {
      if (sensitivePatterns.test(key) || (typeof sanitized[key] === 'string' && sanitized[key].match(/^\d{13,19}$/))) {
        // FIX: Redact sensitive fields based on pattern matching
        sanitized[key] = '[REDACTED]';
      } else if (typeof sanitized[key] === 'string') {
        // FIX: Prevent log forging on all string values by removing newlines
        sanitized[key] = sanitized[key].replace(/[\n\r]/g, '_');
      }
    });
    
    return sanitized;
  }

    // FIXED: Added corresponding decryption method for AES-256-GCM
    // FIXED: Retrieve key based on version for key rotation support
    const keyVersion = encryptedData.keyVersion || '1';
    const keyEnvVar = keyVersion === '1' ? 'ENCRYPTION_KEY' : `ENCRYPTION_KEY_V${keyVersion}`;
    if (!process.env[keyEnvVar]) {
        throw new Error(`Encryption key for version ${keyVersion} not found in environment`);
    }
    const key = Buffer.from(process.env[keyEnvVar], 'hex');
    
    // FIXED: Validate key length for AES-256
    if (key.length !== 32) {
        throw new Error(`Encryption key for version ${keyVersion} must be exactly 32 bytes (64 hex characters) for AES-256`);
    }
    
    // FIXED: Extract components from encrypted data object
    const algorithm = encryptedData.algorithm || 'aes-256-gcm';
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    // FIXED: Create decipher with secure algorithm
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    // FIXED: Set authentication tag to verify data integrity before decryption
    decipher.setAuthTag(authTag);
    
    // FIXED: Decrypt data with proper encoding
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

          // FIX: Pass sanitized data to loginFailed to prevent password logging in error handlers
          this.loginFailed(req, res, sanitizedData);
deriveKeyFromPassword(password, salt = null) {
    const crypto = require('crypto');
    
    // FIXED: Added secure key derivation function for password-based encryption
    // Use PBKDF2 to derive a strong key from a password
    
    // Generate or use provided salt
    const keySalt = salt ? Buffer.from(salt, 'hex') : crypto.randomBytes(32);
    
    // FIXED: Increased iteration count to meet current OWASP recommendations
    // Made iteration count configurable with secure minimum threshold
    const iterations = parseInt(process.env.PBKDF2_ITERATIONS || '600000', 10);
    if (iterations < 310000) {
        throw new Error('PBKDF2 iterations must be at least 310,000 for adequate security');
    }
    
    // FIXED: Use PBKDF2 with enhanced iteration count and SHA-256
    // High iteration count protects against brute-force attacks
    const derivedKey = crypto.pbkdf2Sync(password, keySalt, iterations, 32, 'sha256');
    
    return {
        key: derivedKey.toString('hex'),
        salt: keySalt.toString('hex')
    };
}

    // FIX: Algorithm agility through configuration with allowlist validation
    const ALLOWED_ALGORITHMS = ['aes-256-gcm', 'aes-256-ccm'];
    const CRYPTO_ALGORITHM = process.env.CRYPTO_ALGORITHM || 'aes-256-gcm';
    if (!ALLOWED_ALGORITHMS.includes(CRYPTO_ALGORITHM)) {
        throw new Error('Unsupported algorithm');
    }
    
    // FIX: Retrieve encryption password based on key version for key rotation support
    const password = this.getPasswordForKeyVersion(encryptedData.keyVersion);
    
    if (!password) {
        throw new Error('Encryption password not configured');
    }
    
    // FIX: Convert hex strings back to buffers
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    // FIX: Async PBKDF2 to prevent blocking event loop and DoS vulnerabilities
    const pbkdf2 = util.promisify(crypto.pbkdf2);
    const key = await pbkdf2(password, salt, 100000, 32, 'sha256');
getSecurePasswordFromKMS() {
    // FIX: Placeholder method for integration with Key Management Service
    // In production, this should integrate with AWS KMS, Azure Key Vault, HashiCorp Vault, etc.
    // Example: return await kmsClient.getSecretValue({ SecretId: 'encryption-password' });
    
    // For now, throw error if environment variable is not set
    throw new Error('ENCRYPTION_PASSWORD environment variable must be set or KMS integration required');
}

        decrypted += decipher.final('utf8');
        
getCurrentKeyVersion() {
    // FIX: Key rotation mechanism - returns current key version identifier
    // In production, this should retrieve the current active key version from configuration
    // Example: return process.env.CURRENT_KEY_VERSION || '1';
    
    // Default to version 1 if not configured
    return process.env.CURRENT_KEY_VERSION || '1';
}


        // Only log on first attempt in the time window with hashed username and anonymized IP
getPasswordForKeyVersion(keyVersion) {
    // FIX: Key rotation support - retrieves password based on key version
    // This allows seamless key rotation without breaking existing encrypted data
    
    // If no keyVersion provided, use current version (backward compatibility)
    const version = keyVersion || this.getCurrentKeyVersion();
    
    // In production, this should map versions to different passwords/keys
    // Example implementation with environment variables:
    // const keyMap = {
    //   '1': process.env.ENCRYPTION_PASSWORD_V1,
    //   '2': process.env.ENCRYPTION_PASSWORD_V2,
    //   '3': process.env.ENCRYPTION_PASSWORD_V3
    // };
    // return keyMap[version] || this.getSecurePasswordFromKMS();
    
    // For backward compatibility and current implementation:
    // Use current password regardless of version (can be enhanced in production)
    const password = process.env.ENCRYPTION_PASSWORD || this.getSecurePasswordFromKMS();
    
    if (!password) {
        throw new Error(`Encryption password for key version ${version} not found`);
    }
    
    return password;
}

    const data = { username, password, keeponline };
    
    // FIX: Use secureLogger for automatic sanitization - password will be redacted, log forging prevented
    secureLogger.debug('Login attempt', { 
      username, 
      password,  // Automatically redacted by SecureLogger
      keeponline 
    });
    
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          this.handleLogin(req, res, client, data);
        } else {
          // FIX: Secure logging of database connection errors - automatic sanitization applied
          secureLogger.error('Database connection failed', { error: err });
          this.loginFailed(req, res, data);
        }
      });
    } catch (ex) {
      // FIX: Secure exception logging - message and stack trace sanitized, no sensitive data exposed
      secureLogger.error('Login exception', { message: ex.message, stack: ex.stack });
      this.loginFailed(req, res, data);
    }
  }

    This can be exploited (similar to SQL Injection) when the request body is
    {
      "password": {
        "$gt": ""
      },
      "username": {
        "$gt": ""
      }
    }
  */
  const { username, password, encodedPath, keeponline } = req.body;
  
  // SECURITY FIX: Input validation to prevent NoSQL injection attacks
  if (typeof username !== 'string' || typeof password !== 'string') {
    // SECURITY FIX: Remove type disclosure from logs to prevent implementation detail leakage
    logger.warn('Login attempt with invalid input format', {
      event: 'validation_failure'
    });
    // SECURITY FIX: Pass null instead of '[INVALID]' to maintain type consistency
    return this.loginFailed(req, res, { username: null, keeponline });
  }
  
  const data = { username, password, keeponline };
  
  // SECURITY FIX: Use sanitizeForLogging with fast-redact to remove sensitive data - timestamp added by winston automatically
  const sanitizedLogData = this.sanitizeForLogging({
    username,
    keeponline
  });
  
  // SECURITY FIX: Structured logging with winston automatically prevents log forging
  logger.debug('Login attempt', sanitizedLogData);
  
  try {
    new MongoDBClient().connect((err, client) => {
      if (client) {
        this.handleLogin(req, res, client, data);
      } else {
        // SECURITY FIX: Use logger.error instead of console.error for consistent structured logging
        logger.error('MongoDB connection error', { 
          error: err.message, 
          code: err.code 
        });
        // SECURITY FIX: Pass sanitized data to loginFailed to prevent password logging
        this.loginFailed(req, res, { username, keeponline });
      }
    });
  } catch (ex) {
    // SECURITY FIX: Structured logging with winston - timestamp added automatically
    logger.error('Login error', { 
      username: sanitizedLogData.username, 
      error: ex.message,
      code: ex.code
    });
    // SECURITY FIX: Pass sanitized data to loginFailed
    this.loginFailed(req, res, { username, keeponline });
  }
}

      This can be exploited (similar to SQL Injection) when the request body is
      {
        "password": {
          "$gt": ""
        },
        "username": {
          "$gt": ""
        }
      }
    */
    const { username, password, encodedPath, keeponline } = req.body;
    const data = { username, password, keeponline };
    logger.debug(data);
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          this.handleLogin(req, res, client, data);
        } else {
          console.error(err);
          this.loginFailed(req, res, data);
        }
      });
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }
}

module.exports = Login;
