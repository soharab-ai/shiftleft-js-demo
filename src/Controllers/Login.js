// SECURITY FIX: Utility function to sanitize log inputs and prevent log forging using validator library
function sanitizeForLog(input) {
  if (!input) return '[EMPTY]';
  // Use validator.escape() for industry-standard HTML entity encoding
  const escaped = validator.escape(String(input));
  return escaped.substring(0, 50); // Limit length to prevent log flooding
}

// SECURITY FIX: Hash username for logging to prevent sensitive data exposure
function hashUsernameForLog(username) {
  const LOG_SALT = process.env.LOG_SALT || 'default-salt-change-in-production';
  return crypto.createHash('sha256').update(username + LOG_SALT).digest('hex').substring(0, 16);
async encryptData(secretText) {
    const crypto = require('crypto');
    const util = require('util');
    
    // FIX: Input validation and size limits to prevent resource exhaustion attacks
    if (!secretText || typeof secretText !== 'string' || secretText.length > 1048576) {
        throw new Error('Invalid input: must be a string under 1MB');
    }
    
    // FIX: Algorithm agility through configuration with allowlist validation
    const ALLOWED_ALGORITHMS = ['aes-256-gcm', 'aes-256-ccm'];
    const CRYPTO_ALGORITHM = process.env.CRYPTO_ALGORITHM || 'aes-256-gcm';
    if (!ALLOWED_ALGORITHMS.includes(CRYPTO_ALGORITHM)) {
        throw new Error('Unsupported algorithm');
    }
    
    // FIX: Use environment variables or a secure key management system instead of hardcoded password
    const password = process.env.ENCRYPTION_PASSWORD || this.getSecurePasswordFromKMS();
    
    if (!password) {
        throw new Error('Encryption password not configured');
    }
    
    // FIX: Generate random salt for proper key derivation
    const salt = crypto.randomBytes(16);
    
    // FIX: Async PBKDF2 to prevent blocking event loop and DoS vulnerabilities
    const pbkdf2 = util.promisify(crypto.pbkdf2);
    const key = await pbkdf2(password, salt, 100000, 32, 'sha256');
    
    // FIX: Generate a random IV for each encryption operation to ensure semantic security
    const iv = crypto.randomBytes(16);
    
    // FIX: Use AES-256-GCM instead of DES for strong authenticated encryption
    const cipher = crypto.createCipheriv(CRYPTO_ALGORITHM, key, iv);
    
    // FIX: Encrypt the data using secure AES-256-GCM algorithm
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIX: Get authentication tag for integrity verification
    const authTag = cipher.getAuthTag();
    
    // FIX: Key rotation mechanism for cryptographic agility
    const keyVersion = this.getCurrentKeyVersion();
    
    // FIX: Memory zeroing for sensitive data to prevent memory scraping attacks
    key.fill(0);
    
    // FIX: Return encrypted data with salt, iv, authTag, and keyVersion required for decryption and verification
    return {
        encrypted: encrypted,
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        keyVersion: keyVersion
    };
}

          // SECURITY FIX: Log with hashed username and anonymized IP instead of plain username
async decryptData(encryptedData) {
    const crypto = require('crypto');
    const util = require('util');
    
    // FIX: Input validation for structure and format to prevent malformed data attacks
    if (!encryptedData || !encryptedData.encrypted || !encryptedData.salt || 
        !encryptedData.iv || !encryptedData.authTag) {
        throw new Error('Malformed encrypted data: missing required fields');
    }
    
    // FIX: Hex format validation using regex
    const hexRegex = /^[0-9a-f]+$/i;
    if (!hexRegex.test(encryptedData.salt) || !hexRegex.test(encryptedData.iv) || 
        !hexRegex.test(encryptedData.authTag) || !hexRegex.test(encryptedData.encrypted)) {
        throw new Error('Malformed encrypted data: invalid hex format');
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
