const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');

const encryptionKey = "This is a simple key, don't guess it";
class Order {
  hex(key) {
    // Hash Key
    return key;
encryptData(plainText) {
    // FIX: Define cryptographic constants for maintainability and validation
    const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
    const IV_LENGTH = 16;
    const KEY_LENGTH = 32;
    const SALT_LENGTH = 32;
    
    // FIX: Validate algorithm availability before use
    if (!crypto.getCiphers().includes(ENCRYPTION_ALGORITHM)) {
      throw new Error('Unsupported cipher algorithm');
    }
    
    // FIX: Validate encryption key/passphrase exists - fail fast on missing configuration
    if (!process.env.ENCRYPTION_KEY) {
      throw new Error('ENCRYPTION_KEY environment variable not configured');
    }
    
    // FIX: Generate a cryptographic salt for key derivation
    const salt = crypto.randomBytes(SALT_LENGTH);
    
    // FIX: Validate salt generation succeeded
    if (!salt || salt.length !== SALT_LENGTH) {
      throw new Error('Failed to generate secure random salt');
    }
    
    // FIX: Use scrypt KDF to derive a proper 32-byte key from the passphrase
    const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, salt, KEY_LENGTH);
    
    // FIX: Validate derived key length
    if (key.length !== KEY_LENGTH) {
      throw new Error('Invalid key length after derivation');
    }
    
    // FIX: Generate a random IV for each encryption operation to prevent pattern analysis
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // FIX: Validate IV generation succeeded
    if (!iv || iv.length !== IV_LENGTH) {
      throw new Error('Failed to generate secure random IV');
    }
    
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
    
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIX: Get authentication tag for GCM mode to ensure data integrity
    const authTag = cipher.getAuthTag();
    
    // FIX: Return salt, IV, authTag, and encrypted data together for secure decryption
    return {
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      encryptedData: encrypted
    };
  }

      
      // FIX: Validate salt is exactly 32 bytes when decoded
      const saltBuffer = Buffer.from(encryptedObject.salt, 'hex');
      if (saltBuffer.length !== SALT_LENGTH) {
        throw new Error('Invalid encrypted data format');
      }
      
      // FIX: Validate IV is exactly 16 bytes when decoded
      const ivBuffer = Buffer.from(encryptedObject.iv, 'hex');
      if (ivBuffer.length !== IV_LENGTH) {
        throw new Error('Invalid encrypted data format');
      }
      
      // FIX: Validate authTag is exactly 16 bytes when decoded
      const authTagBuffer = Buffer.from(encryptedObject.authTag, 'hex');
      if (authTagBuffer.length !== AUTH_TAG_LENGTH) {
        throw new Error('Invalid encrypted data format');
      }
      
      // FIX: Use scrypt KDF to derive the same key from passphrase and salt
      const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, saltBuffer, KEY_LENGTH);
      
      // FIX: Validate derived key length
      if (key.length !== KEY_LENGTH) {
        throw new Error('Invalid key length after derivation');
      }
      
      const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, ivBuffer);
      
      // FIX: Set authentication tag for GCM mode verification
      decipher.setAuthTag(authTagBuffer);
      
      let decrypted = decipher.update(encryptedObject.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      // FIX: Prevent timing attacks and information leakage by returning generic error message
      throw new Error('Decryption failed');
constantTimeCompare(a, b) {
    try {
      // FIX: Validate inputs exist before processing
      if (!a || !b) {
        return false;
      }
      
      // FIX: Convert to buffers safely
      const bufA = Buffer.from(a);
      const bufB = Buffer.from(b);
      
      // FIX: Check lengths match before comparison to prevent timingSafeEqual exceptions
      if (bufA.length !== bufB.length) {
        return false;
      }
      
      // FIX: Implement constant-time comparison to prevent timing-based side-channel attacks
      return crypto.timingSafeEqual(bufA, bufB);
    } catch (error) {
      // FIX: Return false on any error to maintain constant-time properties
      return false;
    }
  }

      const newOrders = orders.filter(order => orderId !== order.orderId);
      req.session.orders = this.encryptData(JSON.stringify(newOrders));
      console.log(newOrders);
    }
    res.send(200);
  }

  checkout(req, res) {
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      let totalPrice = 0;
      for (let index = 0; index < orders.length; index += 1) {
        totalPrice += orders[index].price;
      }
      this.processCC(req, res, orders, totalPrice);
    }
    console.log(req.session.orders);
  }

  createStripeRequest(creditCard, price, address) {
    const STRIPE_CLIENT_ID = 'AKIA2E0A8F3B244C9986';
    const STRIPE_CLIENT_SECRET_KEY = '7CE556A3BC234CC1FF9E8A5C324C0BB70AA21B6D';
    https.request(
      `http://invalidstripe.com?STRIPE_CLIENT_ID=${STRIPE_CLIENT_ID}&STRIPE_CLIENT_SECRET_KEY=${STRIPE_CLIENT_SECRET_KEY}&price=${price}&address=${JSON.stringify(
        address
      )}`
    );
  }

  async processCC(req, res, orders, totalPrice) {
    try {
      const self = this;
      new MongoDBClient().connect(async function(err, client) {
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
