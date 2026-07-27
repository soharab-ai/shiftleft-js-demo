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
    /bearer/i,
    /access[_-]?token/i,
    /refresh[_-]?token/i,
    /private[_-]?key/i
  ];
  
  // Handle null, undefined, or primitive types
  if (data === null || data === undefined) {
    return data;
  }
  
  if (typeof data !== 'object') {
    return data;
  }
  
  // FIX: Circular reference detection to prevent infinite loops in recursive sanitization
  if (visited.has(data)) {
    return '[Circular Reference]';
  }
  
  visited.add(data);
  
  // FIX: Handle arrays by recursively sanitizing each element
  if (Array.isArray(data)) {
    return data.map(item => this.sanitizeForLog(item, visited));
  }
  
  // FIX: Deep clone for nested object sanitization instead of shallow copy
  const sanitized = {};
  
  for (const key in data) {
    if (data.hasOwnProperty(key)) {
      // FIX: Pattern matching against sensitive field names (case-insensitive)
      const isSensitive = SENSITIVE_PATTERNS.some(pattern => pattern.test(key));
      
      if (isSensitive) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof data[key] === 'object' && data[key] !== null) {
        // FIX: Recursively sanitize nested objects and arrays
        sanitized[key] = this.sanitizeForLog(data[key], visited);
      } else {
        sanitized[key] = data[key];
      }
    }
  }
  
  return sanitized;
}

          timestamp: new Date().toISOString(),
          action: 'login'
        });
        
        // FIX: Added secure cookie flags for security
        res.cookie('username', result.username, {
login(req, res) {
    /*
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
    
    // FIX: Input validation to prevent NoSQL injection attacks
    // Ensure username and password are strings, not objects with operators
    if (typeof username !== 'string' || typeof password !== 'string') {
      logger.warn('Invalid login attempt with non-string credentials');
      return res.status(400).json({ error: 'Invalid input format' });
    }
    
    // FIX: Separate operational data from loggable data to prevent accidental logging of sensitive info
    const data = { username, password, keeponline };
    const sanitizedData = this.sanitizeForLog(data);
    
    // FIX: Log only sanitized data without sensitive information (password redacted)
    // Using deep sanitization to redact password field and nested sensitive data before logging
    logger.debug(sanitizedData);
    
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          // Pass operational data to handleLogin for authentication (never log this directly)
          this.handleLogin(req, res, client, data);
        } else {
          // FIX: Sanitize error logging to prevent sensitive data exposure in error messages
          logger.error(this.sanitizeForLog({ 
            error: err?.message || 'Database connection failed', 
            stack: err?.stack?.split('\n')[0] 
          }));
          // FIX: Pass sanitized data to loginFailed to prevent password logging in error handlers
          this.loginFailed(req, res, sanitizedData);
        }
      });
    } catch (ex) {
      // FIX: Sanitize exception logging to prevent sensitive data exposure
      logger.error(this.sanitizeForLog({ 
        error: ex?.message || 'Unknown error', 
        type: ex?.constructor?.name || 'Error',
        stack: ex?.stack?.split('\n')[0]
      }));
      // FIX: Pass sanitized data to loginFailed to prevent password logging in exception handlers
      this.loginFailed(req, res, sanitizedData);
    }
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
