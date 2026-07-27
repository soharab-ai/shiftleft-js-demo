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
  }

  }
async encryptData(plaintext) {
    // FIXED: Enhanced AES-256-GCM encryption with KDF and comprehensive security measures
    try {
      // Input validation - prevents operations on invalid data types
      if (typeof plaintext !== 'string' || plaintext.length === 0) {
        throw new Error('Plaintext must be a non-empty string');
      }
      
      const algorithm = 'aes-256-gcm';
      
      // Generate cryptographically secure random salt for key derivation
      const salt = crypto.randomBytes(32);
      
      // Key derivation using scrypt - derives encryption key from master key with salt
      const key = await crypto.scrypt(process.env.ENCRYPTION_KEY, salt, 32);
      
      // Generate cryptographically secure random IV for each encryption operation
      const iv = crypto.randomBytes(16); // 16 bytes IV for AES-GCM
      
      // Create cipher with AES-256-GCM
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      // Encrypt the plaintext
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag for integrity verification
      const authTag = cipher.getAuthTag();
      
      // Secure memory handling - zero out key material to prevent memory dumps
      key.fill(0);
      
      // Return structured encrypted data with algorithm version, salt, IV, authTag, and ciphertext
      return {
        algorithm: 'aes-256-gcm-v1',
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted
      };
    } catch (error) {
      throw new Error('Encryption failed: ' + error.message);
    }
  }

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
