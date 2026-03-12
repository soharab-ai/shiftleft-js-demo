const logger = require('../Logger').logger;
const MongoDBClient = require('../DB').MongoDBClient;

class Login {
  loginFailed(req, res, { username, password, keeponline }) {
    res.locals.username = username;
    res.locals.password = password;
    res.locals.keeponline = keeponline;
    res.locals.message = 'Failed to Sign in. Please verify credentials';
    res.redirect('/login');
  }

encryptData(secretText) {
    const crypto = require('crypto');

    // FIX: Replaced weak DES encryption with strong AES-256-GCM encryption
    const algorithm = 'aes-256-gcm';
    
    // FIX: Mandatory key validation - no fallback to randomBytes
    // Verify ENCRYPTION_KEY exists and is exactly 64 hexadecimal characters
    if (!process.env.ENCRYPTION_KEY || !/^[0-9a-f]{64}$/i.test(process.env.ENCRYPTION_KEY)) {
        throw new Error('ENCRYPTION_KEY must be set as a 64-character hexadecimal string');
    }
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    
    // FIX: Validate key length is exactly 32 bytes for AES-256
    if (key.length !== 32) {
        throw new Error('ENCRYPTION_KEY must be exactly 32 bytes (256 bits)');
    }
    
    // FIX: Generate random initialization vector for each encryption operation
    const iv = crypto.randomBytes(16); // 128-bit IV
    
    // FIX: Create cipher with secure algorithm, proper key and IV
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // FIX: Use update() and final() methods to complete encryption process properly
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIX: Get authentication tag for GCM mode (provides integrity verification)
    const authTag = cipher.getAuthTag();
    
    // FIX: Return encrypted data with IV and auth tag required for decryption
    return {
        encrypted: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
decryptData(encryptedData, iv, authTag) {
    const crypto = require('crypto');
    
    // FIX: Input validation for encrypted data parameter
    if (!encryptedData || typeof encryptedData !== 'string' || !/^[0-9a-f]*$/i.test(encryptedData)) {
        throw new Error('Invalid encrypted data format');
    }
    
    // FIX: Input validation for IV parameter - must be 32 hex characters (16 bytes)
    if (!iv || !/^[0-9a-f]{32}$/i.test(iv)) {
        throw new Error('IV must be a 32-character hexadecimal string');
    }
    
    // FIX: Input validation for authentication tag parameter - must be 32 hex characters (16 bytes)
    if (!authTag || !/^[0-9a-f]{32}$/i.test(authTag)) {
        throw new Error('Authentication tag must be a 32-character hexadecimal string');
    }
    
    // Use same strong algorithm for decryption
    const algorithm = 'aes-256-gcm';
    
    // FIX: Mandatory key validation - no fallback to randomBytes
    // Retrieve the same key used for encryption from secure storage
    if (!process.env.ENCRYPTION_KEY || !/^[0-9a-f]{64}$/i.test(process.env.ENCRYPTION_KEY)) {
        throw new Error('ENCRYPTION_KEY must be set as a 64-character hexadecimal string');
    }
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    
    // FIX: Validate key length is exactly 32 bytes for AES-256
    if (key.length !== 32) {
        throw new Error('ENCRYPTION_KEY must be exactly 32 bytes (256 bits)');
    }
    
    // Create decipher with algorithm, key, and IV
    const decipher = crypto.createDecipheriv(
        algorithm, 
        key, 
        Buffer.from(iv, 'hex')
    );
    
    // Set authentication tag for integrity verification
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

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
