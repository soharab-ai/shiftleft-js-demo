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
    
    // Fixed: Validate ENCRYPTION_SALT environment variable exists and has minimum length
    if (!process.env.ENCRYPTION_SALT || Buffer.from(process.env.ENCRYPTION_SALT, 'hex').length < 16) {
      throw new Error('ENCRYPTION_SALT environment variable must be configured with minimum 16 bytes');
    }
    
    // Fixed: Replaced weak DES encryption with strong AES-256-GCM encryption
    const algorithm = 'aes-256-gcm';
    
    // Fixed: Generate cryptographically secure random IV (12 bytes for GCM mode)
    const iv = crypto.randomBytes(12);
    
    // Fixed: Use proper key derivation with scrypt and secure salt from environment variable
    // Fixed: Added explicit scrypt parameters for OWASP-recommended security levels
    const key = crypto.scryptSync(
      process.env.ENCRYPTION_SECRET, 
      process.env.ENCRYPTION_SALT, 
      32,
      { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }
    );
    
    // Fixed: Create cipher with AES-256-GCM algorithm for authenticated encryption
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // Fixed: Encrypt the data with proper encoding
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Fixed: Get authentication tag for data integrity verification
    const authTag = cipher.getAuthTag();
    
    // Fixed: Return version identifier for key rotation mechanism, IV, encrypted data, and auth tag
    return {
      version: process.env.ENCRYPTION_KEY_VERSION || '1',
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag: authTag.toString('hex')
    };
  }

    // Fixed: Added try-catch block to handle decryption failures and prevent information leakage
    try {
      // Fixed: Decrypt the data with proper encoding
      let decrypted = decipher.update(encryptedObject.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      // Fixed: Generic error message to prevent information disclosure while indicating decryption failure
      throw new Error('Decryption failed: data may be corrupted or tampered');
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
