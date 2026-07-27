// FIX: Added centralized secure logging wrapper to prevent sensitive data exposure and log forging attacks
// This class automatically sanitizes sensitive fields and escapes control characters
const validator = require('validator');

class SecureLogger {
  constructor(baseLogger) {
    this.logger = baseLogger;
    // FIX: Comprehensive list of sensitive fields to redact from logs
    this.sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'creditCard', 'ssn', 'authToken'];
  }
  
  // FIX: Prevents log forging by escaping special characters and removing newlines/carriage returns
  sanitizeValue(value) {
    if (typeof value === 'string') {
      // Escape HTML/special characters and remove newline characters to prevent log injection
      return validator.escape(value).replace(/[\n\r]/g, '');
    }
    return value;
  }
  
  // FIX: Recursively sanitizes objects to redact sensitive fields and prevent log forging
  sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return this.sanitizeValue(obj);
    
    const result = Array.isArray(obj) ? [] : {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (this.sensitiveFields.includes(key)) {
          // Redact sensitive fields completely
          result[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object') {
          // Recursively sanitize nested objects
          result[key] = this.sanitizeObject(obj[key]);
        } else {
          // Sanitize primitive values to prevent log forging
          result[key] = this.sanitizeValue(obj[key]);
        }
      }
    }
    return result;
  }
  
  debug(message, data) {
    this.logger.debug(this.sanitizeValue(message), this.sanitizeObject(data));
  }
  
  warn(message, data) {
    this.logger.warn(this.sanitizeValue(message), this.sanitizeObject(data));
  }
  
  error(message, data) {
    this.logger.error(this.sanitizeValue(message), this.sanitizeObject(data));
  }
}

// FIX: Initialize secure logger wrapper to enforce safe logging throughout the application
const secureLogger = new SecureLogger(logger);

          fname: result.fname,
          lname: result.lname,
          passportnum: result.passportnum,
          address1: result.address1,
          address2: result.address2,
          zipCode: result.zipCode
        };
        const creditInfo = encryptData(result.creditCard);
  // FIX: Added input validation to prevent NoSQL injection attacks
  // Ensures username and password are strings, not objects containing MongoDB operators
  validateLoginInput(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') {
      throw new Error('Invalid input: username and password must be strings');
    }
    return true;
  }


        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }

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
    
    // FIX: Validate input types to prevent NoSQL injection attacks
    // Reject requests where username or password are not strings
    try {
      this.validateLoginInput(username, password);
    } catch (validationError) {
      // FIX: Use secureLogger to automatically sanitize log output and prevent log forging
      secureLogger.warn('Login validation failed - invalid input type', { 
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
