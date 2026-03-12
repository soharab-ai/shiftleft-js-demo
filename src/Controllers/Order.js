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
    // FIXED: Added input validation to prevent denial-of-service and type errors
    if (!secretText || typeof secretText !== 'string') {
        throw new TypeError('secretText must be a non-empty string');
    }
    if (secretText.length > 1048576) { // 1MB limit
        throw new RangeError('secretText exceeds maximum allowed size');
    }
    
    // FIXED: Replaced weak DES encryption with secure AES-256-GCM authenticated encryption
    const algorithm = 'aes-256-gcm';
    
    // FIXED: Use proper 256-bit key with versioning support for key rotation
    const keyData = this.getEncryptionKey();
    const key = keyData.key;
    const keyVersion = keyData.version;
    
    // FIXED: Generate random IV for each encryption operation to ensure security
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIXED: Get authentication tag for authenticated encryption (ensures integrity)
    const authTag = cipher.getAuthTag();
    
    // FIXED: Return encrypted data with IV, auth tag, and key version for secure decryption
    return {
        encrypted: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        keyVersion: keyVersion
    };
  }

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        // FIXED: Log detailed error securely without exposing to end users
        console.error('Decryption failed:', error.message);
        // FIXED: Return generic message to prevent information disclosure
        throw new Error('Failed to decrypt data');
    }
  }

  addToOrder(req, res) {
    const order = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      order.id = crypto.randomBytes(256).toString('hex');
      orders.push(order);
      req.session.orders = this.encryptData(JSON.stringify(orders));
    }
    res.send(200);
getEncryptionKey(keyVersion = null) {
    // FIXED: Secure key management with version support for key rotation
    // This method retrieves the key from a secure key management service
    // For production: use AWS KMS, Azure Key Vault, HashiCorp Vault, etc.
    
    // FIXED: Support key versioning for rotation strategy
    const activeKeyVersion = keyVersion || process.env.KEY_VERSION || 'v1';
    const keyFromEnv = process.env[`ENCRYPTION_KEY_${activeKeyVersion}`];
    
    if (keyFromEnv && Buffer.from(keyFromEnv, 'hex').length === 32) {
        // Note: Use crypto.timingSafeEqual() for comparing keys or secrets to prevent timing attacks
        return {
            key: Buffer.from(keyFromEnv, 'hex'),
            version: activeKeyVersion
        };
    }
    
    // FIXED: Fail-fast in production to prevent silent data loss
    if (process.env.NODE_ENV === 'production') {
        throw new Error(`ENCRYPTION_KEY_${activeKeyVersion} must be configured in production environment`);
    }
    
    // FIXED: Only allow key generation in development/test environments
    console.warn('WARNING: Using generated key for development only. Configure ENCRYPTION_KEY environment variable for production.');
    return {
        key: crypto.randomBytes(32),
        version: activeKeyVersion
    };
  }

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
