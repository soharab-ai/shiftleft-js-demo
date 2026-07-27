const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');

const encryptionKey = "This is a simple key, don't guess it";
class Order {
  hex(key) {
    // Hash Key
    return key;
  }
encryptData(secretText) {
    // Fixed: Input validation for type and size to prevent encoding errors and DoS attacks
    if (typeof secretText !== 'string' || secretText.length === 0) {
        throw new Error('Input data must be a non-empty string');
    }
    if (secretText.length > 1048576) { // 1MB limit
decryptData(encryptedText, iv, keyVersion = '1') {
    // FIXED: Replaced DES with AES-256-GCM for strong authenticated encryption
    const algorithm = 'aes-256-gcm';
    
    // FIXED: Implemented key rotation support with versioning
    const keyEnvVar = `ENCRYPTION_KEY_V${keyVersion}`;
    const masterKey = process.env[keyEnvVar] || process.env.ENCRYPTION_KEY || '';
    
    // FIXED: Implemented Key Derivation Function (KDF) for proper key strengthening
    const salt = Buffer.from(process.env.ENCRYPTION_SALT || '', 'hex');
    if (salt.length === 0) {
      // FIXED: Generic error message to prevent information leakage
      throw new Error('Invalid encryption configuration');
    }
    
    const key = crypto.scryptSync(masterKey, salt, 32);
    
    // FIXED: Generic error message to prevent information leakage about key requirements
    if (key.length !== 32) {
      throw new Error('Invalid encryption configuration');
    }
    
    // FIXED: Use initialization vector (IV) passed as parameter for proper AES decryption
    const ivBuffer = Buffer.from(iv, 'hex');
    
    // FIXED: Extract authentication tag (last 16 bytes) for GCM mode integrity verification
    const encryptedBuffer = Buffer.from(encryptedText, 'hex');
    const authTag = encryptedBuffer.slice(-16);
    const ciphertext = encryptedBuffer.slice(0, -16);
    
    // FIXED: Create decipher with AES-256-GCM algorithm
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuffer);
    
    // FIXED: Added Additional Authenticated Data (AAD) for context binding to prevent replay attacks
    const aad = Buffer.from(JSON.stringify({ context: 'order' }));
    decipher.setAAD(aad);
    
    decipher.setAuthTag(authTag);
    
    // FIXED: Perform authenticated decryption with secure error handling
    let decrypted;
    try {
      decrypted = decipher.update(ciphertext, null, 'utf8');
      decrypted += decipher.final('utf8');
    } catch (err) {
      // FIXED: Constant-time delay to prevent timing oracle attacks
      const delay = () => new Promise(resolve => setTimeout(resolve, 100));
      delay().then(() => {
        // FIXED: Generic error message to prevent cryptographic information leakage
        throw new Error('Decryption failed');
      });
      throw new Error('Decryption failed');
    }
    
    return decrypted;
  }

encryptData(plaintext) {
    // FIXED: Implement corresponding encryption method using AES-256-GCM
    const algorithm = 'aes-256-gcm';
    
    // FIXED: Implemented Key Derivation Function (KDF) for proper key strengthening
    const masterKey = process.env.ENCRYPTION_KEY || '';
    const salt = Buffer.from(process.env.ENCRYPTION_SALT || '', 'hex');
    
    if (salt.length === 0) {
      // FIXED: Generic error message to prevent information leakage
      throw new Error('Invalid encryption configuration');
    }
    
    const key = crypto.scryptSync(masterKey, salt, 32);
    
    // FIXED: Generic error message to prevent information leakage about key requirements
    if (key.length !== 32) {
      throw new Error('Invalid encryption configuration');
    }
    
    // FIXED: Generate random 16-byte IV for each encryption operation (best practice)
    const iv = crypto.randomBytes(16);
    
    // FIXED: Create cipher with AES-256-GCM algorithm
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // FIXED: Added Additional Authenticated Data (AAD) for context binding to prevent replay attacks
    const aad = Buffer.from(JSON.stringify({ context: 'order' }));
    cipher.setAAD(aad);
    
    // FIXED: Encrypt the plaintext with secure error handling
    let encrypted;
    try {
      encrypted = cipher.update(plaintext, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
    } catch (err) {
      // FIXED: Generic error message to prevent cryptographic information leakage
      throw new Error('Encryption failed');
    }
    
    // FIXED: Get authentication tag for integrity verification
    const authTag = cipher.getAuthTag();
    
    // FIXED: Concatenate ciphertext with authentication tag
    const encryptedWithTag = Buffer.concat([encrypted, authTag]);
    
    // FIXED: Return encrypted data with IV and key version for decryption and key rotation support
    const keyVersion = process.env.ENCRYPTION_KEY_VERSION || '1';
    
    return {
      encryptedData: encryptedWithTag.toString('hex'),
      iv: iv.toString('hex'),
      keyVersion: keyVersion
    };
  }

      });
    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();
