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
    // Weak encryption
    const desCipher = crypto.createCipheriv('des', encryptionKey);
    return desCipher.update(secretText, 'utf8', 'hex');
  }

decryptData(encryptedData) {
    // FIXED: Enhanced decryption with algorithm agility, key versioning, and context binding
    try {
      // Validate input structure
      if (!encryptedData || !encryptedData.encryptedText || !encryptedData.authTag || !encryptedData.iv) {
        throw new Error('Invalid encrypted data format');
      }

      // FIXED: Validate authentication tag length to prevent timing attacks
      if (encryptedData.authTag.length !== 16) {
        throw new Error('Invalid authentication tag');
      }

      // FIXED: Algorithm agility - validate algorithm version
      const algorithm = encryptedData.algorithm || 'aes-256-gcm';
      const version = encryptedData.version || 1;
      
      if (algorithm !== 'aes-256-gcm' || version !== 1) {
        throw new Error('Unsupported encryption format');
      }

      // FIXED: Key rotation support - retrieve versioned key
      const keyVersion = encryptedData.keyVersion || 'current';
      const encryptionKey = this.getEncryptionKey(keyVersion);

      // Use AES-256-GCM for cryptographically secure decryption
      const decipher = crypto.createDecipheriv(algorithm, encryptionKey, encryptedData.iv);
      
      // FIXED: Context binding - set Additional Authenticated Data (AAD) for context validation
      if (encryptedData.context) {
        decipher.setAAD(Buffer.from(encryptedData.context, 'utf8'));
      }
      
      // Set authentication tag to verify data integrity and authenticity
      decipher.setAuthTag(encryptedData.authTag);
      
      let decrypted = decipher.update(encryptedData.encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      // Prevent cryptographic details exposure in error messages
      throw new Error('Decryption failed: Data may be tampered or corrupted');
    }
  }

      // Generate a random 16-byte IV for each encryption operation
      const iv = crypto.randomBytes(16);
      
      // FIXED: Get current key version for key rotation support
      const currentKeyVersion = process.env.CURRENT_KEY_VERSION || 'current';
      const encryptionKey = this.getEncryptionKey(currentKeyVersion);
      
      // Create cipher with AES-256-GCM for authenticated encryption
      const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
      
      // FIXED: Context binding - create cryptographic context for AAD
      const context = JSON.stringify({
        userId: contextData.userId || this.userId || 'unknown',
        purpose: contextData.purpose || 'order-data',
        timestamp: Date.now()
      });
      
      // FIXED: Set Additional Authenticated Data to bind ciphertext to context
getEncryptionKey(keyVersion = 'current') {
    // FIXED: Enhanced key management with key derivation and key rotation support
    // FIXED: Key rotation mechanism - support versioned keys
    const keyIdentifier = `ENCRYPTION_KEY_${keyVersion.toUpperCase()}`;
    const masterSecret = process.env[keyIdentifier] || process.env.MASTER_SECRET;
    
    if (!masterSecret) {
      throw new Error('Encryption key not configured');
    }
    
    // FIXED: Use key derivation function (PBKDF2) for stronger security
    // Derive key from master secret using PBKDF2 with salt
    const keySalt = process.env.KEY_SALT || 'default-salt-change-in-production';
    
    if (keySalt === 'default-salt-change-in-production') {
      console.warn('WARNING: Using default salt. Configure KEY_SALT environment variable for production.');
    }
    
    const derivedKey = crypto.pbkdf2Sync(
      masterSecret,
      keySalt,
      100000,  // iterations - computationally expensive to prevent brute-force
      32,      // key length for AES-256 (32 bytes = 256 bits)
      'sha256' // hash algorithm
    );
    
    // Validate that key is exactly 32 bytes (256 bits) for AES-256
    if (derivedKey.length !== 32) {
      throw new Error('Invalid encryption key configuration: Key must be 32 bytes (256 bits)');
    }
    
migrateFromDESToAES(encryptedText, legacyDESKey, legacyIV = null, contextData = {}) {
    // FIXED: Enhanced migration utility with proper IV handling for complete DES data migration
    // This method handles the migration of existing DES-encrypted data
    try {
      // FIXED: Accept legacy IV as parameter to handle data encrypted with non-zero IVs
      const desIV = legacyIV || Buffer.alloc(8, 0);
      
      // Validate DES key length (8 bytes for DES)
      if (legacyDESKey.length !== 8) {
        throw new Error('Invalid DES key length');
      }
      
      // Step 1: Decrypt data using legacy DES key and IV
      const desDecipher = crypto.createDecipheriv('des', legacyDESKey, desIV);
      let decrypted = desDecipher.update(encryptedText, 'hex', 'utf8');
      decrypted += desDecipher.final('utf8');
      
      // Step 2: Re-encrypt using new AES-256-GCM implementation with context binding
      const reencrypted = this.encryptData(decrypted, contextData);
      
      // Log migration event for audit purposes (without exposing sensitive data)
      console.log('Data successfully migrated from DES to AES-256-GCM');
      
      return reencrypted;
    } catch (error) {
      // Log migration failure for monitoring
      console.error('Migration failed: Unable to decrypt with legacy DES key or re-encrypt with AES');
      throw new Error('Data migration failed');
    }
  }

rotateEncryptionKey(encryptedData, newKeyVersion) {
    // FIXED: New method to support key rotation for existing encrypted data
    try {
      // Step 1: Decrypt with current key version
      const decrypted = this.decryptData(encryptedData);
      
      // Step 2: Re-encrypt with new key version
      const oldKeyVersion = process.env.CURRENT_KEY_VERSION;
      process.env.CURRENT_KEY_VERSION = newKeyVersion;
      
      const contextData = encryptedData.context ? JSON.parse(encryptedData.context) : {};
      const reencrypted = this.encryptData(decrypted, contextData);
      
      // Restore old key version
      process.env.CURRENT_KEY_VERSION = oldKeyVersion;
      
      // Log key rotation event for audit
      console.log(`Data re-encrypted from key version ${encryptedData.keyVersion} to ${newKeyVersion}`);
      
      return reencrypted;
    } catch (error) {
      console.error('Key rotation failed:', error.message);
      throw new Error('Key rotation failed');
    }
  }
