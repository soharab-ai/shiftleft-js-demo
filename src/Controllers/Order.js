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
        throw new Error('Input data exceeds maximum allowed size');
    }

    // Fixed: Validate encryption key environment variable exists
    if (!process.env.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY environment variable is not configured');
    }

    // Fixed: Replaced weak DES encryption with strong AES-256-GCM encryption
    const algorithm = 'aes-256-gcm';
    
    // Fixed: Generate a unique random initialization vector (16 bytes for AES) for semantic security
    const iv = crypto.randomBytes(16);
    
    // Fixed: Generate unique salt for key derivation to strengthen key security
    const salt = crypto.randomBytes(16);
    
    // Fixed: Use PBKDF2 key derivation function with salt for enhanced security
    const key = crypto.pbkdf2Sync(process.env.ENCRYPTION_KEY, salt, 100000, 32, 'sha256');
    
    // Fixed: Key validation to ensure correct key length for AES-256
    if (key.length !== 32) {
        throw new Error('Derived encryption key must be exactly 32 bytes for AES-256');
    }
    
    // Fixed: Create cipher with AES-256-GCM algorithm
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // Fixed: Encrypt the data with proper encoding
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Fixed: Get the authentication tag for authenticated encryption
decryptData(encryptedObj) {
    // Fixed: Validate encryption key environment variable exists
    if (!process.env.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY environment variable is not configured');
    }

    // Added: Companion decryption method using AES-256-GCM for secure data decryption
    const algorithm = 'aes-256-gcm';
    
    // Fixed: Retrieve salt from encrypted object for key derivation
    const salt = Buffer.from(encryptedObj.salt, 'hex');
    
    // Fixed: Derive the same key used for encryption using PBKDF2 with salt
    const key = crypto.pbkdf2Sync(process.env.ENCRYPTION_KEY, salt, 100000, 32, 'sha256');
    
    // Fixed: Key validation to ensure correct key length for AES-256
    if (key.length !== 32) {
        throw new Error('Derived encryption key must be exactly 32 bytes for AES-256');
    }
    
    // Convert hex strings back to buffers for decryption
    const iv = Buffer.from(encryptedObj.iv, 'hex');
    const authTag = Buffer.from(encryptedObj.authTag, 'hex');
    
    // Create decipher with AES-256-GCM algorithm
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    // Fixed: Structured exception handling for authentication tag verification and tampering detection
    try {
        // Decrypt the data and verify authentication tag
        let decrypted = decipher.update(encryptedObj.encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        // Log the error securely without exposing cryptographic details
        console.error('Decryption failed: Data integrity check failed');
        throw new Error('Decryption failed: Invalid data or authentication tag');
    }
  }

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
          console.log(transaction);
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
      });
    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();
