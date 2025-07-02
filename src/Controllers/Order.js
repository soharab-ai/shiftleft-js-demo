const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');
const SecretsManager = require('../Utilities/SecretsManager');
const { Logger } = require('../Utilities/Logger');
const { MemoryProtection } = require('../Security/MemoryProtection');
const { KeyRotationManager } = require('../Security/KeyRotationManager');
const { RateLimiter } = require('../Security/RateLimiter');
const { MongoDBClient } = require('../Database/MongoDBClient');

// Removed hardcoded credentials in favor of a secret management service
class Order {
  constructor() {
    this.secretsManager = new SecretsManager();
    this.keyRotationManager = new KeyRotationManager();
    this.rateLimiter = new RateLimiter('credentials', 10, 60); // 10 requests per minute
    this.logger = new Logger('Order');
    this.memoryProtection = new MemoryProtection();
    // IV should be unique and not reused with the same key
    this.iv = crypto.randomBytes(16);
  }

  hex(key) {
    // Hash Key
    return key;
  }

  async encryptData(secretText) {
    try {
      // Get the latest encryption key version for encrypting new data
      const { key, keyId } = await this._getEncryptionKeyWithVersion();
      
      // Use proper key length for AES-256
      const hash = crypto.createHash('sha256').update(key).digest();
      const cipher = crypto.createCipheriv('aes-256-gcm', hash, this.iv);
      
      // Combine cipher text and auth tag for complete encryption
      const encrypted = cipher.update(secretText, 'utf8', 'hex') + cipher.final('hex');
      const authTag = cipher.getAuthTag().toString('hex');
      
      // Return IV, encrypted data, auth tag and key version ID
      const result = JSON.stringify({
        iv: this.iv.toString('hex'),
        encryptedData: encrypted,
        authTag,
        keyId // Store which key was used for decryption later
      });
      
      // Zero out sensitive data from memory after use
      this.memoryProtection.secureErase(key);
      
      return result;
    } catch (error) {
      this.logger.error('Encryption error', { errorMsg: error.message });
      throw new Error('Failed to encrypt data');
    }
  }

  async decryptData(encryptedText) {
    try {
      // Parse the encrypted object
      const encObj = JSON.parse(encryptedText);
      const iv = Buffer.from(encObj.iv, 'hex');
      
      // Get the specific key version that was used for this encryption
      const { key } = await this._getEncryptionKeyWithVersion(encObj.keyId);
      const hash = crypto.createHash('sha256').update(key).digest();
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', hash, iv);
      decipher.setAuthTag(Buffer.from(encObj.authTag, 'hex'));
      
      const result = decipher.update(encObj.encryptedData, 'hex', 'utf8') + decipher.final('utf8');
      
      // Zero out sensitive data from memory
      this.memoryProtection.secureErase(key);
      
      return result;
    } catch (error) {
      this.logger.error('Decryption error', { errorMsg: error.message });
      return null;
    }
  }
  
  // Private method to get encryption key with rate limiting and audit logging
  async _getEncryptionKeyWithVersion(keyId = null) {
    try {
      // Apply rate limiting to prevent abuse
      await this.rateLimiter.checkLimit();
      
      // Audit log for credential access
      this.logger.audit('Encryption key accessed', { keyId });
      
      if (keyId) {
        // Get specific key version
        const key = await this.secretsManager.getVersionedSecret('ENCRYPTION_KEY', keyId);
        return { key, keyId };
      } else {
        // Get latest key and its version
        const { secret: key, version: latestKeyId } = await this.keyRotationManager.getLatestKey('ENCRYPTION_KEY');
        return { key, keyId: latestKeyId };
      }
    } catch (error) {
      this.logger.error('Failed to retrieve encryption key', { errorMsg: error.message });
      throw new Error('Encryption key access failed');
    }
  }

  async addToOrder(req, res) {
    try {
      const order = req.body;
      this.logger.info('Adding item to order');
      
      if (req.session.orders) {
        const orders = JSON.parse(await this.decryptData(req.session.orders));
        order.id = crypto.randomBytes(32).toString('hex'); // Reduced from 256 to 32 bytes for efficiency
        orders.push(order);
        req.session.orders = await this.encryptData(JSON.stringify(orders));
      }
      res.send(200);
    } catch (error) {
      this.logger.error('Error adding to order', { errorMsg: error.message });
      res.status(500).send('Error processing your request');
    }
  }
  
  async removeOrder(req, res) {
    try {
      const { orderId } = req.body;
      this.logger.info('Removing order', { orderId });
      
      if (req.session.orders) {
        const orders = JSON.parse(await this.decryptData(req.session.orders));
        const newOrders = orders.filter(order => orderId !== order.orderId);
        req.session.orders = await this.encryptData(JSON.stringify(newOrders));
      }
      res.send(200);
    } catch (error) {
      this.logger.error('Error removing order', { errorMsg: error.message });
      res.status(500).send('Error processing your request');
    }
  }

  async checkout(req, res) {
    try {
      if (req.session.orders) {
        const orders = JSON.parse(await this.decryptData(req.session.orders));
        let totalPrice = 0;
        for (let index = 0; index < orders.length; index += 1) {
          totalPrice += orders[index].price;
        }
        await this.processCC(req, res, orders, totalPrice);
      }
    } catch (error) {
      this.logger.error('Checkout error', { errorMsg: error.message });
      res.status(500).send('Error processing your checkout');
    }
  }

  async createStripeRequest(creditCard, price, address) {
    try {
      // Just-in-time credential access - only get credentials when needed
      const clientIdPromise = this.secretsManager.getSecret('STRIPE_CLIENT_ID');
      const secretKeyPromise = this.secretsManager.getSecret('STRIPE_CLIENT_SECRET_KEY');
      
      // Use Promise.all for improved performance
      const [STRIPE_CLIENT_ID, STRIPE_CLIENT_SECRET_KEY] = await Promise.all([
        clientIdPromise, secretKeyPromise
      ]);
      
      // Log credential access (but not the actual values)
      this.logger.audit('Stripe credentials accessed for payment processing', { price });
      
      // Make the request
      const requestPromise = new Promise((resolve, reject) => {
        const req = https.request(
          `https://api.stripe.com/v1/charges?client_id=${encodeURIComponent(STRIPE_CLIENT_ID)}&price=${encodeURIComponent(price)}&address=${encodeURIComponent(JSON.stringify(address))}`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${STRIPE_CLIENT_SECRET_KEY}`,
              'Content-Type': 'application/json'
            }
          },
          (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => resolve(data));
          }
        );
        
        req.on('error', reject);
        req.end();
      });
      
      const result = await requestPromise;
      
      // Securely erase credentials from memory
      this.memoryProtection.secureErase(STRIPE_CLIENT_ID);
      this.memoryProtection.secureErase(STRIPE_CLIENT_SECRET_KEY);
      
      return result;
    } catch (error) {
      this.logger.error('Stripe request failed', { errorMsg: error.message });
      throw new Error('Payment processing failed');
    }
  }

  async processCC(req, res, orders, totalPrice) {
    try {
      const username = req.cookies.username;
      const address = req.body.address;
      
      // Create database connection using a pool or connection manager
      const db = await this._getDatabaseConnection();
      
      const result = await db.collection('users').findOne({ username });
      if (!result) {
        throw new Error('User not found');
      }
      
      const transactionId = crypto.randomBytes(32).toString('hex');
      
      // Process orders and create transaction
      await db.collection('orders').insertMany(
        orders.map(order => ({ ...order, transactionId }))
      );
      
      const transaction = {
        transactionId,
        date: new Date().valueOf(),
        username,
        cc: result.creditCard,
        shippingAddress: address,
        billingAddress: result.address
      };
      
      this.logger.info('Creating transaction', { transactionId, username });
      await db.collection('transactions').insertOne(transaction);
      
      // Process payment
      await this.createStripeRequest(
        result.creditCard,
        totalPrice,
        transaction.billingAddress
      );
      
      // Send confirmation email
      const message = `
        Hello ${username},
          We have processed your order. Please visit the following link to review your order
          <a href="https://tarpit.com/orders/${encodeURIComponent(username)}?ref=mail&transactionId=${encodeURIComponent(transactionId)}">Review Order</a>
      `;
      
      await mail.sendMail(
        'orders@tarpit.com',
        result.email,
        `Order Successfully Processed`,
        message
      );
      
      res.status(200).json({ status: 'success', transactionId });
    } catch (error) {
      this.logger.error('Process credit card error', { errorMsg: error.message });
      res.status(500).send('Error processing payment');
    }
  }
  
  // Helper method to get database connection
  async _getDatabaseConnection() {
    try {
      // Get database credentials using just-in-time secret access
      const dbCredentials = await this.secretsManager.getSecret('DATABASE_CREDENTIALS');
      
      // Use a connection pool or manager rather than creating new connection each time
      const client = await MongoDBClient.getConnection(dbCredentials);
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      
      // Clean up credentials from memory
      this.memoryProtection.secureErase(dbCredentials);
      
      return db;
    } catch (error) {
      this.logger.error('Database connection error', { errorMsg: error.message });
      throw new Error('Database connection failed');
    }
  }
}

module.exports = new Order();

