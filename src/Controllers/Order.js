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
/**
 * Decrypts data using AES-256-GCM with proper key management and validation
 * @param {Buffer} encryptedText - The encrypted data
 * @param {Buffer} iv - Initialization vector (16 bytes)
 * @param {Buffer} authTag - Authentication tag for GCM mode
 * @param {string} keyVersion - Version identifier for the encryption key
 * @returns {Buffer} - The decrypted data
 */
async decryptData(encryptedText, iv, authTag, keyVersion = 'current') {
  try {
    // Validate inputs to ensure security
    if (!Buffer.isBuffer(encryptedText) || !Buffer.isBuffer(iv) || !Buffer.isBuffer(authTag)) {
      throw new Error('Invalid input format');
    }
    
    if (iv.length !== 16) {
      throw new Error('IV must be 16 bytes for AES-256-GCM');
    }

    // Retrieve encryption key from secure vault instead of using a hardcoded key
    // Implementation of key rotation - use keyVersion to fetch the appropriate key
    const keyVaultName = process.env.KEY_VAULT_NAME;
    const keyVaultUrl = `https://${keyVaultName}.vault.azure.net`;
    const credential = new DefaultAzureCredential();
    const secretClient = new SecretClient(keyVaultUrl, credential);
    
    const secretName = `encryption-key-${keyVersion}`;
    const secretResponse = await secretClient.getSecret(secretName);
    
    // Apply key derivation using PBKDF2 to strengthen the key
    const salt = process.env.KEY_DERIVATION_SALT || 'default-salt-change-me';
    const derivedKey = crypto.pbkdf2Sync(
      secretResponse.value,
      salt,
      100000, // 100,000 iterations for key stretching
      32, // 32 bytes = 256 bits for AES-256
      'sha512'
    );
    
    // Validate key length for AES-256
    if (derivedKey.length !== 32) {
      throw new Error('Invalid key length for AES-256');
    }

    // Create decipher using AES-256-GCM (authenticated encryption)
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    
    // Set authentication tag for authenticated encryption
    decipher.setAuthTag(authTag);
    
    // Proper decryption with both update and final methods
    const decryptedData = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    
    return decryptedData;
  } catch (error) {
    // Added error handling without revealing sensitive details
    console.error('Decryption failed:', error.message);
    throw new Error('Decryption failed');
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
  }
  removeOrder(req, res) {
    const { orderId } = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
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
