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
    
    // FIXED: Generate random salt for key derivation
    const salt = crypto.randomBytes(16);
    
    // FIXED: Use async scrypt for non-blocking key derivation with explicit parameters for security hardening
    const scryptAsync = util.promisify(crypto.scrypt);
    const key = await scryptAsync(password, salt, 32, { N: 32768, r: 8, p: 1 });
    
    // FIXED: Generate random IV for each encryption operation
    const iv = crypto.randomBytes(16);
    
    // FIXED: Use AES-256-GCM instead of DES
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // FIXED: Properly encrypt using update() and final() methods
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIXED: Get authentication tag for data integrity verification
    const authTag = cipher.getAuthTag();
    
    // FIXED: Return encrypted data with salt, iv, and authTag for decryption
    return {
        encrypted: encrypted,
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

    // FIXED: Validate input structure to prevent attacks from malformed data
    if (!encryptedData || typeof encryptedData !== 'object') {
        throw new Error('Invalid encrypted data format: must be an object');
    }

    // FIXED: Validate all required fields exist and are valid hex strings
    const requiredFields = ['encrypted', 'salt', 'iv', 'authTag'];
    for (const field of requiredFields) {
        if (!encryptedData[field] || typeof encryptedData[field] !== 'string' || !/^[0-9a-f]+$/i.test(encryptedData[field])) {
            throw new Error(`Invalid or missing ${field} in encrypted data`);
        }
    }

    // FIXED: Validate correct lengths for cryptographic components
    if (Buffer.from(encryptedData.salt, 'hex').length !== 16) {
        throw new Error('Invalid salt length');
    }
    if (Buffer.from(encryptedData.iv, 'hex').length !== 16) {
        throw new Error('Invalid IV length');
    }
    if (Buffer.from(encryptedData.authTag, 'hex').length !== 16) {
        throw new Error('Invalid authentication tag length');
    }
    
    // FIXED: Validate encryption key from environment variable - fail fast if not properly configured
    if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length < 32) {
        throw new Error('ENCRYPTION_KEY must be set in environment variables and be at least 32 characters long');
    }
    
    const password = process.env.ENCRYPTION_KEY;
    
    // FIXED: Reconstruct salt from hex string
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
