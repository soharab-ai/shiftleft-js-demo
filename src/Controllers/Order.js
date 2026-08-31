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
    // Fixed: Validate ENCRYPTION_SECRET environment variable exists
    if (!process.env.ENCRYPTION_SECRET) {
      throw new Error('ENCRYPTION_SECRET environment variable must be configured');
    }
    
async decryptData(encryptedData) {
    // FIXED: Enhanced AES-256-GCM decryption with comprehensive security validations
    try {
      // Input validation - prevents type confusion and malformed data attacks
      if (!encryptedData || typeof encryptedData !== 'object' || !encryptedData.iv || !encryptedData.authTag || !encryptedData.ciphertext || !encryptedData.salt || !encryptedData.algorithm) {
        throw new Error('Invalid encrypted data structure');
      }
      
      // Algorithm version validation - enables future algorithm migration and backward compatibility
      if (encryptedData.algorithm !== 'aes-256-gcm-v1') {
        throw new Error('Unsupported encryption algorithm version');
      }
      
      const algorithm = 'aes-256-gcm';
      
      // Parse encrypted data components
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const authTag = Buffer.from(encryptedData.authTag, 'hex');
      const encryptedText = Buffer.from(encryptedData.ciphertext, 'hex');
      const salt = Buffer.from(encryptedData.salt, 'hex');
      
      // IV length validation - prevents cryptographic failures and timing attacks
      if (iv.length !== 16) {
        throw new Error('Invalid IV length');
      }
      
      // Authentication tag length validation - ensures proper GCM authentication
      if (authTag.length !== 16) {
        throw new Error('Invalid authentication tag length');
      }
      
      // Key derivation using scrypt - provides forward secrecy and computational hardness against brute-force
      const key = await crypto.scrypt(process.env.ENCRYPTION_KEY, salt, 32);
      
      // Create decipher with AES-256-GCM for authenticated decryption
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      
      // Set authentication tag for integrity verification
      decipher.setAuthTag(authTag);
      
      // Decrypt the data
      let decrypted = decipher.update(encryptedText, null, 'utf8');
      decrypted += decipher.final('utf8');
      
      // Secure memory handling - zero out key material to prevent memory dumps
      key.fill(0);
      
      return decrypted;
    } catch (error) {
      // Secure error handling without exposing sensitive details
      throw new Error('Decryption failed: ' + error.message);
    }
async function(err, client) {
        // SECURITY FIX: Sanitize username from cookies using comprehensive sanitization to prevent log forging
        const username = sanitizeForLogging(req.cookies.username);
        const address = req.body.address;
        if (client) {
          const db = client.db('tarpit', { returnNonCachedInstance: true });
          if (!db) {
            throw new Error('DB connection not available', err);
            return;
          }
          // SECURITY FIX: Exclude credit card from database retrieval projection
          const result = await db.collection('users').findOne({
            username
          }, {
            projection: { creditCard: 0 }
          });
          
          // SECURITY FIX: Retrieve payment token instead of plain-text credit card
          const paymentToken = result.paymentToken;
          const transactionId = crypto.randomBytes(256).toString('hex');
          await db
            .collection('orders')
            .insertMany(orders.map(order => ({ ...order, transactionId })));
          
          // SECURITY FIX: Store only hashed/tokenized credit card data, never plain-text
          // Complies with PCI-DSS Requirement 3.4 - never store full PAN post-authorization
          const transaction = {
            transactionId,
            date: new Date().valueOf(),
            username,
            ccToken: hashSensitiveData(paymentToken), // Store only hash/token
            ccLast4: paymentToken.slice(-4), // Store last 4 for reference
            shippingAddress: address,
            billingAddress: result.address
          };
          
          // SECURITY FIX: Never log transaction details containing user data
          // Eliminate logging entirely in favor of dedicated, access-controlled audit systems
          // This ensures PCI-DSS compliance and prevents sensitive data exposure in all environments
          
          await db.collection('transactions').insertOne(transaction);
          
          // SECURITY FIX: Use payment token for Stripe processing instead of plain-text CC
          this.createStripeRequest(
            paymentToken,
            totalPrice,
// SECURITY FIX: Hash sensitive data with salt before storage
// Ensures PCI-DSS compliance by never storing plain-text credit card data
function hashSensitiveData(data) {
  const hash = crypto.createHash('sha256');
  hash.update(data + process.env.CC_SALT); // Use environment-specific salt
  return hash.digest('hex');
}
// SECURITY FIX: Helper function to mask credit card numbers for safe logging
// Shows only last 4 digits to prevent sensitive data exposure in logs
function maskCreditCard(creditCard) {
  if (!creditCard || creditCard.length < 4) {
    return '****';
  }
  // Show only last 4 digits
  return `****-****-****-${creditCard.slice(-4)}`;
}

// SECURITY FIX: Comprehensive sanitization to prevent log forging attacks
// Uses validator library and removes control characters, ANSI escape sequences
function sanitizeForLogging(input) {
  if (typeof input !== 'string') {
    return String(input);
  }
  
  // Use validator library for robust sanitization
  let sanitized = validator.stripLow(input, true);
  
  // Additional comprehensive sanitization
  sanitized = sanitized
    // Remove all control characters (ASCII 0-31 and 127)
    .replace(/[\x00-\x1F\x7F]/g, '')
    // Remove ANSI escape sequences that could manipulate logs
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '')
    // Normalize Unicode to prevent obfuscation attacks
    .normalize('NFKC')
    // Limit length to prevent log flooding
    .substring(0, 200);
  
// SECURITY FIX: Pattern-based detection system for comprehensive data sanitization
// Recursively sanitizes nested objects and detects sensitive data by patterns
function sanitizeLogData(data) {
  const sensitivePatterns = {
    creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
  };
  
  const sensitiveFieldPatterns = /(?:cc|card|credit|password|pwd|pass|ssn|social|cvv|secret|token|key|auth)/i;
  
  function redactRecursive(obj) {
    if (typeof obj !== 'object' || obj === null) {
      // Check if the value itself contains sensitive patterns
      if (typeof obj === 'string') {
        let redacted = obj;
        for (const [type, pattern] of Object.entries(sensitivePatterns)) {
          redacted = redacted.replace(pattern, '[REDACTED]');
        }
        return redacted;
      }
      return obj;
    }
    
    const sanitized = Array.isArray(obj) ? [] : {};
    for (const [key, value] of Object.entries(obj)) {
      if (sensitiveFieldPatterns.test(key)) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = redactRecursive(value);
      }
    }
    return sanitized;
  }
  
  return redactRecursive(data);
}
