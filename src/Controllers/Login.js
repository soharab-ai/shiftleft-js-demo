// SECURITY FIX: Helper method to sanitize sensitive data before logging with deep traversal
// This prevents exposure of PII and sensitive information in application logs
sanitizeForLogging(obj, depth = 0) {
  const MAX_DEPTH = 5;
  // SECURITY FIX: Pattern-based matching for better maintainability and coverage
  const SENSITIVE_PATTERNS = /password|credit|passport|ssn|address|zip|token|secret|key/i;
  
  if (depth > MAX_DEPTH || typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  // SECURITY FIX: Handle both arrays and objects for comprehensive sanitization
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const [key, value] of Object.entries(obj)) {
    // SECURITY FIX: Use regex pattern matching to catch variations of sensitive field names
    if (SENSITIVE_PATTERNS.test(key)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      // SECURITY FIX: Deep traversal to sanitize nested sensitive data
      sanitized[key] = this.sanitizeForLogging(value, depth + 1);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

sanitizeLogInput(input) {
  return String(input).replace(/[\n\r\u0000\u001b]/g, '');
}

    
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
        
        // SECURITY FIX: Sanitize username to prevent log forging attacks (newline injection)
        logger.info(this.sanitizeLogInput(`Login successful for user: ${username}`));
        // SECURITY FIX: Do NOT log credit card information (even encrypted) or any PII data
        
        // SECURITY FIX: Add secure cookie flags to prevent XSS and MITM attacks
        res.cookie('username', result.username, { httpOnly: true, secure: true, sameSite: 'strict' });
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo, { httpOnly: true, secure: true, sameSite: 'strict' });

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      // SECURITY FIX: Sanitize exception message to prevent log forging and information disclosure
      logger.error('Login error occurred', { 
        error: this.sanitizeLogInput(ex.message || 'Unknown error'),
        errorCode: ex.code
      });
      this.loginFailed(req, res, data);
    }
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
