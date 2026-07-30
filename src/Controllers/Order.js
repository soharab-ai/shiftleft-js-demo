const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');
// FIX: Load encryption key once from secure environment variable at module initialization
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex') : null;

// FIX: Validate that encryption key exists and has correct length (32 bytes for AES-256)
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be set as a 64-character hex string (32 bytes)');
}

encryptData(secretText) {
    // FIX: Use AES-256-GCM for strong cryptographic security (replacing weak DES)
    const algorithm = 'aes-256-gcm';
    
    // FIX: Use the securely loaded encryption key from module-level constant instead of generating new key per operation
    const key = ENCRYPTION_KEY;
    
    // FIX: Generate a random initialization vector for each encryption operation
    const iv = crypto.randomBytes(16); // 16-byte IV for GCM mode
    
    // FIX: Create cipher using AES-256-GCM algorithm with secure key and IV
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // FIX: Encrypt the data
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIX: Get authentication tag for authenticated encryption (prevents tampering)
    const authTag = cipher.getAuthTag();
decryptData(encryptedData) {
    // FIX: Use AES-256-GCM for decryption to complement secure encryption implementation
    const algorithm = 'aes-256-gcm';
    
    // FIX: Use the same securely loaded encryption key from module-level constant
    const key = ENCRYPTION_KEY;
    
    // FIX: Convert hex strings back to buffers
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    // FIX: Create decipher with AES-256-GCM
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
    // FIX: Set authentication tag for verification (ensures data integrity)
    decipher.setAuthTag(authTag);
    
    // FIX: Decrypt the data
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

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
