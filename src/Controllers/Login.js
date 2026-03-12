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
    // FIX: Removed hardcoded credentials and replaced with environment variable
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    // FIX: Added validation to ensure encryption key is configured with security guidance
    if (!encryptionKey) {
        throw new Error('Encryption key not configured. Set ENCRYPTION_KEY environment variable using a secrets management service (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault) or encrypted configuration. Never commit keys to version control.');
    }
    
    // FIX: Validate minimum key length for security using byte length instead of character length
    const keyBuffer = Buffer.from(encryptionKey, 'utf8');
    if (keyBuffer.length < 32) {
        throw new Error('Encryption key must be at least 32 bytes when encoded in UTF-8.');
    }
    
    // FIX: Implement key format validation to prevent weak keys
    const uniqueChars = new Set(encryptionKey).size;
    if (uniqueChars < 16) {
        throw new Error('Encryption key has insufficient entropy. Use a cryptographically secure random key generator.');
    }
    
    // FIX: Replaced weak DES algorithm with strong AES-256-GCM encryption
    const algorithm = 'aes-256-gcm';
    
    // FIX: Generate random initialization vector for each encryption operation
    const iv = crypto.randomBytes(16);
    
    // FIX: Removed default fallback salt to prevent hardcoded credentials vulnerability
    const salt = process.env.ENCRYPTION_SALT;
    if (!salt) {
        throw new Error('Encryption salt not configured. Please set ENCRYPTION_SALT environment variable.');
    }
    
    // FIX: Use scrypt key derivation function to derive secure encryption key
    const key = crypto.scryptSync(encryptionKey, salt, 32);
    
    // FIX: Create cipher with strong algorithm and derived key
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // FIX: Encrypt data using utf8 input and hex output encoding
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIX: Get authentication tag for GCM mode to ensure data integrity
    const authTag = cipher.getAuthTag();
    
    // FIX: Return encrypted data with IV and auth tag only, removed algorithm field to minimize information disclosure
    return {
        encrypted: encrypted,
        iv: iv.toString('hex'),
decryptData(encryptedData) {
    // FIX: Added corresponding decrypt method for secure decryption
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    // FIX: Validate encryption key is configured with security guidance
    if (!encryptionKey) {
        throw new Error('Encryption key not configured. Set ENCRYPTION_KEY environment variable using a secrets management service (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault) or encrypted configuration. Never commit keys to version control.');
    }
    
    // FIX: Validate input structure
    if (!encryptedData || !encryptedData.encrypted || !encryptedData.iv || !encryptedData.authTag) {
        throw new Error('Invalid encrypted data structure.');
    }
    
    // FIX: Removed default fallback salt to prevent hardcoded credentials vulnerability
    const salt = process.env.ENCRYPTION_SALT;
    if (!salt) {
        throw new Error('Encryption salt not configured. Please set ENCRYPTION_SALT environment variable.');
    }
    
    // FIX: Use same key derivation process as encryption
    const key = crypto.scryptSync(encryptionKey, salt, 32);
    
    // FIX: Convert hex strings back to buffers
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    // FIX: Algorithm retrieved from secure configuration instead of encrypted data payload
    const algorithm = 'aes-256-gcm';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    // FIX: Set authentication tag for integrity verification
    decipher.setAuthTag(authTag);
    
    // FIX: Decrypt data
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }


module.exports = Login;
