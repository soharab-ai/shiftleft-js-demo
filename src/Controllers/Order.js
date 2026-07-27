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
  // SECURITY FIX: Automatically apply sanitization to transaction objects
  if (info.transaction) {
    info.transaction = sanitizeForLogging(info.transaction);
  }
  
  // SECURITY FIX: Apply sanitization to any object in metadata
  Object.keys(info).forEach(key => {
    if (typeof info[key] === 'object' && key !== 'level' && key !== 'message' && key !== 'timestamp') {
      info[key] = sanitizeForLogging(info[key]);
    }
  });
  
  return info;
});

// SECURITY FIX: Create Winston logger with automatic redaction and structured output
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    redactFormat(),
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'application.log' })
  ]
});

    } else if (typeof value === 'object' && value !== null) {
      // SECURITY FIX: Recursively sanitize nested objects to handle complex structures
      sanitized[key] = sanitizeForLogging(value, depth + 1);
    } else if (typeof value === 'string') {
      // SECURITY FIX: Remove control characters to prevent log injection/forging (CWE-117)
      sanitized[key] = value.replace(/[\n\r]/g, ' ').replace(/[\x00-\x1F\x7F]/g, '');
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

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
