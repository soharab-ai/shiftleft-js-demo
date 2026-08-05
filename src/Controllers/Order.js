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
getKeyByVersion(version) {
    // ADDED: Key rotation mechanism - retrieves appropriate key based on version identifier
    const keyEnvVar = version === '1' ? 'ENCRYPTION_KEY' : `ENCRYPTION_KEY_V${version}`;
    const masterKey = process.env[keyEnvVar] || process.env.ENCRYPTION_KEY;
    
    // ADDED: Implement PBKDF2 for key derivation from master key material
    const salt = Buffer.from(process.env.KEY_SALT || '0000000000000000000000000000000000000000000000000000000000000000', 'hex');
    const derivedKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
    
    return derivedKey;
  }

decryptData(encryptedData) {
    // FIXED: Replaced weak DES encryption with AES-256-GCM for secure authenticated encryption
    let key;
    let iv;
    
    try {
      // Parse the encrypted data structure containing ciphertext, IV, authentication tag, version, and context
      const { encryptedText, iv: ivHex, authTag, keyVersion, context } = JSON.parse(encryptedData);
      
      // Use AES-256-GCM instead of DES for strong encryption (NIST approved algorithm)
      const algorithm = 'aes-256-gcm';
      
      // ADDED: Retrieve key using version-based key rotation mechanism with PBKDF2 derivation
      const version = keyVersion || '1';
      key = this.getKeyByVersion(version);
      
encryptData(plainText) {
    // FIXED: Added corresponding encryption method using AES-256-GCM
    let key;
    let iv;
    
    try {
      // Use AES-256-GCM for authenticated encryption
      const algorithm = 'aes-256-gcm';
      
      // ADDED: Get current key version for key rotation support
      const keyVersion = process.env.ENCRYPTION_KEY_VERSION || '1';
      
      // ADDED: Retrieve 32-byte (256-bit) encryption key using PBKDF2 derivation
      key = this.getKeyByVersion(keyVersion);
      
      // Validate key length
      if (key.length !== 32) {
        throw new Error('Invalid encryption key length. AES-256 requires 32 bytes.');
      }
      
      // Generate cryptographically secure random 128-bit IV (Initialization Vector)
      iv = crypto.randomBytes(16);
      
      // Create cipher with AES-256-GCM algorithm
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      // ADDED: Create context data for Additional Authenticated Data (AAD) binding
      const contextData = JSON.stringify({
        userId: this.userId || null,
        orderId: this.orderId || null,
        timestamp: Date.now()
      });
      
      // ADDED: Set AAD for context binding to prevent replay and substitution attacks
      cipher.setAAD(Buffer.from(contextData, 'utf8'));
      
      // Encrypt the plaintext
      let encrypted = cipher.update(plainText, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag for integrity verification
      const authTag = cipher.getAuthTag();
      
      // ADDED: Return encrypted data bundle with IV, authentication tag, key version, and context
      return JSON.stringify({
        encryptedText: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        keyVersion: keyVersion,
        context: contextData
      });
    } catch (error) {
      // Handle errors without leaking cryptographic information
      throw new Error('Encryption failed');
    } finally {
      // ADDED: Secure memory handling - zero out sensitive cryptographic material
      if (key) key.fill(0);
      if (iv) iv.fill(0);
    }
  }

        if (this.userId && contextData.userId !== this.userId) {
          throw new Error('Decryption failed');
        }
      }
      
      return decrypted;
    } catch (error) {
      // Handle errors without leaking cryptographic information
      throw new Error('Decryption failed');
    } finally {
      // ADDED: Secure memory handling - zero out sensitive cryptographic material
      if (key) key.fill(0);
      if (iv) iv.fill(0);
    }
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
