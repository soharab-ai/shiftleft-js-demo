// SECURITY FIX: Hash usernames for logging to prevent sensitive data exposure
function hashForLogging(input) {
  if (!input) return 'null';
  return crypto.createHash('sha256')
    .update(String(input))
    .digest('hex')
    .substring(0, 16); // Use first 16 chars for brevity and consistent identifier
}

    res.redirect('/login');
  }

async encryptData(secretText) {
    const crypto = require('crypto');
    const util = require('util');

    // FIXED: Validate encryption key from environment variable - fail fast if not properly configured
    if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length < 32) {
        throw new Error('ENCRYPTION_KEY must be set in environment variables and be at least 32 characters long');
    }
    
    const password = process.env.ENCRYPTION_KEY;
    
async handleLogin(req, res, client, data) {
    const { username, password, keeponline } = data;
    
    // SECURITY FIX: Input validation to prevent injection attacks and ensure safe logging
    if (!username || !password || username.length > 50 || password.length > 50) {
      this.loginFailed(req, res, data);
      return;
    }
    
    // SECURITY FIX: Generate sanitized correlation ID for secure tracing without exposing user identities
    const correlationId = `login_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
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
        
        // SECURITY FIX: Log sanitization to prevent log forging/injection attacks
        // Sanitize userId by removing control characters that could forge log entries
        const sanitizedUserId = result._id 
          ? String(result._id).replace(/[\n\r\t\x00-\x1F\x7F]/g, '_').substring(0, 50)
          : 'N/A';
        
        // SECURITY FIX: Use correlation ID instead of actual userId to prevent enumeration attacks
        logger.info('Login successful - Session initiated', {
          correlationId: correlationId,
          timestamp: new Date().toISOString()
        });
        
        res.cookie('username', result.username);
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo);

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
  // SECURITY FIX: Enhanced sanitization utility to prevent log injection/forging attacks
  // This method filters allowed fields AND sanitizes content to remove control characters
  sanitizeForLogging(obj, allowedFields = []) {
    const sanitized = {};
    allowedFields.forEach(field => {
      if (obj[field] !== undefined) {
        const value = obj[field];
        // SECURITY FIX: Sanitize string values to remove control characters for log forging prevention
        if (typeof value === 'string') {
          // Remove all control characters including null bytes, newlines, carriage returns
          sanitized[field] = value.replace(/[\n\r\t\x00-\x1F\x7F]/g, '_').substring(0, 100);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          sanitized[field] = value;
        } else {
          // For objects/arrays, convert to string and sanitize
          sanitized[field] = String(value).replace(/[\n\r\t\x00-\x1F\x7F]/g, '_').substring(0, 100);
        }
      }
    });
    return sanitized;
  }

    const salt = Buffer.from(encryptedData.salt, 'hex');
    
    // FIXED: Use async scrypt for non-blocking key derivation with explicit parameters matching encryption
    const scryptAsync = util.promisify(crypto.scrypt);
    const key = await scryptAsync(password, salt, 32, { N: 32768, r: 8, p: 1 });
    
    // FIXED: Reconstruct IV from hex string
    const iv = Buffer.from(encryptedData.iv, 'hex');
    
    // FIXED: Create decipher with AES-256-GCM
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    
    // FIXED: Set authentication tag for integrity verification
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    // FIXED: Wrap decryption in try-catch to prevent information disclosure through error messages
    try {
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        // Log the actual error securely (server-side only)
        console.error('Decryption failed:', error.message);
        // Throw a generic error to prevent information leakage
        throw new Error('Decryption failed: invalid data or authentication tag');
    }
}
