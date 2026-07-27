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
}

      return validator.escape(value).replace(/[\n\r]/g, '');
// SECURITY FIX: Anonymize IP addresses to comply with privacy regulations
function anonymizeIP(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  if (ip.includes('.')) {
    // IPv4: mask last octet
    return ip.split('.').slice(0, 3).join('.') + '.0';
  } else if (ip.includes(':')) {
    // IPv6: mask last 80 bits
    return ip.split(':').slice(0, 3).join(':') + '::';
  }
  return 'unknown';
}

    const { username, password, keeponline } = data;
    
    // SECURITY FIX: Initialize failed login attempt tracking for rate-limited logging
    if (!this.failedLoginAttempts) {
      this.failedLoginAttempts = new Map();
    }
    
    try {
      // DB Query
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      if (!db) {
        this.loginFailed(req, res, data);
        return;
      }
      
      // SECURITY FIX: Use parameterized query to prevent NoSQL injection
      const result = await db.collection('users').findOne({
        username: { $eq: username }
      });
      
      // SECURITY FIX: Validate password using bcrypt hash comparison instead of plaintext
      if (result && result.passwordHash) {
        const passwordMatch = await bcrypt.compare(password, result.passwordHash);
        
        if (passwordMatch) {
          // SECURITY FIX: Create user object without sensitive data for session
          const user = {
            fname: result.fname,
            lname: result.lname,
            userId: result._id // Use non-sensitive identifier
          };
          
          // SECURITY FIX: Log with hashed username and anonymized IP instead of plain username
          logger.info(`User login successful - UserHash: ${hashUsernameForLog(username)}, UserId: ${result._id}, Timestamp: ${new Date().toISOString()}, IP: ${anonymizeIP(req.ip)}`);
          
          // SECURITY FIX: Set secure cookie configuration with httpOnly, secure, and sameSite flags
          res.cookie('username', result.username, {
            httpOnly: true,
            secure: true, // Ensures cookie is only sent over HTTPS
            sameSite: 'strict', // Prevents CSRF attacks
            maxAge: 864000000 // Corrected maxAge to milliseconds
          });
          
          // SECURITY FIX: Store minimal user data in session
          req.session.user = JSON.stringify({
            fname: user.fname,
            lname: user.lname,
            userId: user.userId
          });
          req.session.username = username;

          res.redirect('/');
        } else {
          // SECURITY FIX: Implement rate-limited logging for failed login attempts
          const clientIp = req.ip || 'unknown';
          const attemptKey = `${clientIp}_${Date.now() - (Date.now() % 60000)}`; // Group by minute
          if (!this.failedLoginAttempts.has(attemptKey)) {
            this.failedLoginAttempts.set(attemptKey, 0);
          }
          this.failedLoginAttempts.set(attemptKey, this.failedLoginAttempts.get(attemptKey) + 1);

          // Only log on first attempt in the time window with hashed username and anonymized IP
          if (this.failedLoginAttempts.get(attemptKey) === 1) {
            logger.info(`Login failed - UserHash: ${hashUsernameForLog(username)}, IP: ${anonymizeIP(clientIp)}`);
          }

          // Log summary after threshold
          if (this.failedLoginAttempts.get(attemptKey) === 5) {
            logger.warn(`Multiple failed login attempts detected - Count: ${this.failedLoginAttempts.get(attemptKey)}, IP: ${anonymizeIP(clientIp)}, TimeWindow: 1min`);
          }
          
          this.loginFailed(req, res, data);
        }
      } else {
        // SECURITY FIX: Implement rate-limited logging for failed login attempts
        const clientIp = req.ip || 'unknown';
        const attemptKey = `${clientIp}_${Date.now() - (Date.now() % 60000)}`; // Group by minute
        if (!this.failedLoginAttempts.has(attemptKey)) {
          this.failedLoginAttempts.set(attemptKey, 0);
        }
        this.failedLoginAttempts.set(attemptKey, this.failedLoginAttempts.get(attemptKey) + 1);

        // Only log on first attempt in the time window with hashed username and anonymized IP
        if (this.failedLoginAttempts.get(attemptKey) === 1) {
          logger.info(`Login failed - UserHash: ${hashUsernameForLog(username)}, IP: ${anonymizeIP(clientIp)}`);
        }

        // Log summary after threshold
        if (this.failedLoginAttempts.get(attemptKey) === 5) {
          logger.warn(`Multiple failed login attempts detected - Count: ${this.failedLoginAttempts.get(attemptKey)}, IP: ${anonymizeIP(clientIp)}, TimeWindow: 1min`);
        }
        
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      // SECURITY FIX: Log error with hashed username instead of sanitized plain username
      logger.error(`Login error occurred - UserHash: ${hashUsernameForLog(username)}, Error type: ${ex.name || 'Unknown'}`);
      this.loginFailed(req, res, data);
    }
  }

        usernameType: typeof username,
        passwordType: typeof password 
      });
      return res.status(400).json({ error: 'Invalid input format' });
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
