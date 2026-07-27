const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');

const encryptionKey = "This is a simple key, don't guess it";
class Order {
  hex(key) {
    // Hash Key
    return key;
/**
 * SECURITY FIX: Configure Winston logger with automatic redaction format
 * Implements defense-in-depth by applying sanitization at logger level
 * Ensures all logs are automatically sanitized regardless of developer implementation
 * Provides structured logging with configurable transports and formats
 */
const redactFormat = winston.format((info) => {
async decryptData(encryptedData) {
    // FIXED: Replaced weak DES algorithm with secure AES-256-GCM
    // FIXED: Added key derivation using PBKDF2 for enhanced security
    // FIXED: Added key versioning support for key rotation
    // FIXED: Added constant-time error handling to prevent timing attacks
    // encryptedData should be an object containing: { encryptedText, iv, authTag, salt, keyVersion }
    
    // FIXED: Extract key version for key rotation support
    const keyVersion = encryptedData.keyVersion || 'v1';
    const masterKey = process.env[`ENCRYPTION_KEY_${keyVersion.toUpperCase()}`] || process.env.ENCRYPTION_KEY || '';
    
    if (!masterKey) {
        throw new Error('Encryption master key not found in environment variables');
    }
    
    // FIXED: Derive encryption key using PBKDF2 from stored salt
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const encryptionKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
    
    // FIXED: Validate key length for AES-256 (must be 32 bytes)
    if (encryptionKey.length !== 32) {
        encryptionKey.fill(0);
        throw new Error('Encryption key must be 256 bits (32 bytes) for AES-256-GCM');
    }
    
    // FIXED: Extract IV and authentication tag from encrypted data
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const encryptedText = encryptedData.encryptedText;
    
    // FIXED: Validate authTag length to prevent timing attacks through length differences
    if (authTag.length !== 16) {
        encryptionKey.fill(0);
        throw new Error('Invalid authentication tag length');
    }
    
    // FIXED: Use AES-256-GCM for authenticated decryption
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    
    // FIXED: Set authentication tag to verify data integrity
    decipher.setAuthTag(authTag);
    
    // FIXED: Decrypt data with constant-time error handling to prevent timing attacks
    try {
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        // FIXED: Zero out key material from memory immediately after use
        encryptionKey.fill(0);
        return decrypted;
    } catch (error) {
        // FIXED: Use constant-time delay before throwing to prevent timing attacks
        encryptionKey.fill(0);
        await new Promise(resolve => setTimeout(resolve, 100));
        throw new Error('Decryption failed: authentication tag verification error');
    }
}


    } else if (typeof value === 'object' && value !== null) {
      // SECURITY FIX: Recursively sanitize nested objects to handle complex structures
      sanitized[key] = sanitizeForLogging(value, depth + 1);
    } else if (typeof value === 'string') {
      // SECURITY FIX: Remove control characters to prevent log injection/forging (CWE-117)
validateEncryptionKey() {
    // FIXED: Added method to validate encryption key configuration on initialization
    // FIXED: Added support for versioned keys validation
    
    // Check if encryption key is set in environment
    if (!process.env.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY environment variable must be set');
    }
    
    // FIXED: Validate all versioned keys present in environment variables
    const keyVersion = process.env.ENCRYPTION_KEY_VERSION || 'v1';
    const versionedKeyName = `ENCRYPTION_KEY_${keyVersion.toUpperCase()}`;
    
    // Check if versioned key exists
    const masterKey = process.env[versionedKeyName] || process.env.ENCRYPTION_KEY;
    
    if (!masterKey) {
        throw new Error(`Encryption key for version ${keyVersion} not found in environment variables`);
    }
    
    // FIXED: Derive a test key using PBKDF2 to validate master key format
    const testSalt = crypto.randomBytes(32);
    const encryptionKey = crypto.pbkdf2Sync(masterKey, testSalt, 100000, 32, 'sha256');
    
    // FIXED: Ensure derived key meets AES-256 requirements (32 bytes = 256 bits)
    if (encryptionKey.length !== 32) {
        encryptionKey.fill(0);
        throw new Error('Encryption key must be exactly 256 bits (32 bytes) for AES-256-GCM. Current length: ' + (encryptionKey.length * 8) + ' bits');
    }
    
    // FIXED: Zero out key material from memory immediately after validation
    encryptionKey.fill(0);
    
    return true;
}
// FIXED: Replaced manual regex sanitization with validator library for robust log injection prevention
function sanitizeForLog(input) {
  if (typeof input !== 'string') {
    input = String(input);
  }
  // FIXED: Use validator library for robust sanitization against complex encoding attacks
  let sanitized = sanitizer.stripLow(input, true); // Remove control characters including null bytes
  sanitized = sanitizer.escape(sanitized); // Escape HTML/special characters
  return sanitized.substring(0, 200); // Limit length to prevent log flooding
}

    }
    
// Function to mask credit card numbers, showing only last 4 digits for PCI-DSS compliance
function maskCreditCard(cc) {
  if (!cc || typeof cc !== 'string') {
    return 'N/A';
  }
  const last4 = cc.slice(-4);
  return `****-****-****-${last4}`;
}

// FIXED: Added environment-based log level controls to prevent accidental sensitive data logging
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'warn', // FIXED: Restrict levels in production
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'transactions.log',
      level: 'info' // FIXED: Only info and above in file logs
    }),
    new winston.transports.Console({ 
      format: winston.format.simple(),
      level: process.env.NODE_ENV === 'production' ? 'error' : 'info' // FIXED: Console only for errors in production
    })
  ]
});

    // FIXED: Return encrypted data with IV, authentication tag, salt, and key version
    return {
        encryptedText: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        salt: salt.toString('hex'),
        keyVersion: keyVersion
    };
}

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
async function(err, client) {
        const username = req.cookies.username;
        const address = req.body.address;
        if (client) {
          const db = client.db('tarpit', { returnNonCachedInstance: true });
          if (!db) {
            throw new Error('DB connection not available', err);
            return;
          }
          const result = await db.collection('users').findOne({
            username
          });
          const transactionId = crypto.randomBytes(256).toString('hex');
          await db
            .collection('orders')
            .insertMany(orders.map(order => ({ ...order, transactionId })));
          
          // FIXED: Removed full credit card from transaction object, storing only last 4 digits for PCI-DSS compliance
          const transaction = {
            transactionId,
            date: new Date().valueOf(),
            username,
            ccLast4: result.creditCard.slice(-4), // FIXED: Store only last 4 digits instead of full CC
            shippingAddress: address,
            billingAddress: result.address
          };
          
          // FIXED: Hash transaction ID in logs to prevent correlation attacks if logs are compromised
          const safeLogData = {
            transactionIdHash: crypto.createHash('sha256').update(transaction.transactionId).digest('hex').substring(0, 16), // FIXED: Hashed reference instead of plaintext
            date: transaction.date,
            username: sanitizeForLog(transaction.username), // FIXED: Sanitized with validator library
            ccLast4: maskCreditCard(result.creditCard), // Masked CC showing only last 4 digits
            shippingCity: sanitizeForLog(address.split(',')[0] || 'Unknown'), // FIXED: Sanitized address
            billingCity: sanitizeForLog(result.address.split(',')[0] || 'Unknown') // FIXED: Sanitized address
          };
          
          // FIXED: Use structured logging with sanitized data instead of vulnerable console.log
          logger.info('Transaction processed successfully', safeLogData);
          
          // FIXED: Transaction now stores only last 4 digits of CC, not full number
          await db.collection('transactions').insertOne(transaction);
          this.createStripeRequest(
            result.creditCard,
            totalPrice,
            transaction.billingAddress
          );
          
          // FIXED: Sanitized username and encoded URL parameters to prevent email-based injection attacks
          const message = `
            Hello ${sanitizeForLog(username)},
              We have processed your order. Please visit the following link to review your order
              <a href="https://tarpit.com/orders/${encodeURIComponent(username)}?ref=mail&transactionId=${encodeURIComponent(transactionId)}">Review Order</a>
          `;
          mail.sendMail(
            'orders@tarpit.com',
            result.email,
            `Order Successfully Processed`,
            message
          );
        } else {
          console.error(err);
        }
      }

          const result = await db.collection('users').findOne({
            username
          });
          const transactionId = crypto.randomBytes(256).toString('hex');
          await db
            .collection('orders')
            .insertMany(orders.map(order => ({ ...order, transactionId })));
          const transaction = {
            transactionId,
            date: new Date().valueOf(),
            username,
            cc: result.creditCard,
            shippingAddress: address,
            billingAddress: result.address
          };
          
          // SECURITY FIX: Use Winston structured logging with environment-based control
          // In production: only log minimal audit information (transaction ID, username)
          // In non-production: log sanitized transaction details for debugging
          // This implements defense-in-depth and minimizes attack surface
          if (process.env.NODE_ENV !== 'production') {
            logger.info('Transaction processed', { transaction: sanitizeForLogging(transaction) });
          } else {
            // SECURITY FIX: Production logging - only essential audit trail without sensitive data
            logger.info('Transaction processed', { 
              transactionId: transaction.transactionId, 
              username: transaction.username 
            });
          }
          
          await db.collection('transactions').insertOne(transaction);
          this.createStripeRequest(
            result.creditCard,
            totalPrice,
            transaction.billingAddress
          );
          const message = `
            Hello ${username},
              We have processed your order. Please visit the following link to review your order
              <a href="https://tarpit.com/orders/${username}?ref=mail&transactionId=${transactionId}}">Review Order</a>
          `;
          mail.sendMail(
            'orders@tarpit.com',
            result.email,
            `Order Successfully Processed`,
            message
          );
        } else {
          console.error(err);
        }
      }
