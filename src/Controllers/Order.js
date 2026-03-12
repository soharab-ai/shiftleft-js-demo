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
  }

  decryptData(encryptedText) {
    const desCipher = crypto.createDecipheriv('des', encryptionKey);
    return desCipher.update(encryptedText);
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
    // FIX: Use environment variables instead of hardcoded credentials to prevent credential exposure
    const STRIPE_CLIENT_ID = process.env.STRIPE_CLIENT_ID;
    const STRIPE_CLIENT_SECRET_KEY = process.env.STRIPE_CLIENT_SECRET_KEY;
    const STRIPE_CERT_FINGERPRINT = process.env.STRIPE_CERT_FINGERPRINT;
    
    // FIX: Validate that required environment variables are set
    if (!STRIPE_CLIENT_ID || !STRIPE_CLIENT_SECRET_KEY) {
      throw new Error('Stripe credentials not configured. Please set STRIPE_CLIENT_ID and STRIPE_CLIENT_SECRET_KEY environment variables.');
    }
    
    // FIX: Changed from http:// to https:// to ensure encrypted communication
    // This prevents Man-in-the-Middle attacks and ensures data confidentiality and integrity
    const requestData = JSON.stringify({
      amount: Math.round(price * 100), // Stripe expects amount in cents
      currency: 'usd',
      shipping: address
    });
    
    const options = {
      hostname: 'api.stripe.com', // FIX: Use official Stripe API endpoint
      port: 443, // FIX: Use HTTPS port for secure communication
      path: '/v1/charges',
      method: 'POST',
      headers: {
        // FIX: Send credentials in Authorization header instead of URL query parameters
        // This prevents credentials from being logged in server access logs
        'Authorization': `Bearer ${STRIPE_CLIENT_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestData)
      },
      // FIX: Enable certificate validation to prevent MITM attacks
      rejectUnauthorized: true,
      // FIX: Enforce minimum TLS 1.2 to prevent downgrade attacks (POODLE, BEAST)
      minVersion: 'TLSv1.2',
      // FIX: Prefer TLS 1.3 for enhanced security
      maxVersion: 'TLSv1.3',
      // FIX: Restrict to secure ciphers only
      ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      honorCipherOrder: true,
      // FIX: Implement certificate pinning to verify Stripe's specific certificate
      checkServerIdentity: (host, cert) => {
        // Only perform certificate pinning if fingerprint is configured
        if (STRIPE_CERT_FINGERPRINT) {
          const fingerprint = crypto.createHash('sha256')
            .update(cert.raw)
            .digest('hex')
            .toUpperCase()
            .match(/.{2}/g)
            .join(':');
          
          if (fingerprint !== STRIPE_CERT_FINGERPRINT) {
            return new Error('Certificate fingerprint mismatch - potential MITM attack');
          }
        }
        return undefined;
      }
    };
    
    const req = https.request(options, (res) => {
      // FIX: Verify HSTS header to ensure protocol downgrade protection
      const hstsHeader = res.headers['strict-transport-security'];
      if (!hstsHeader || !hstsHeader.includes('max-age=')) {
        console.warn('WARNING: Server does not enforce HSTS - vulnerable to protocol downgrade attacks');
      }
      
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        console.log('Stripe request completed with status:', res.statusCode);
      });
    });
    
    // FIX: Add connection timeout to prevent slowloris attacks and hanging connections
    req.setTimeout(10000, () => {
      req.destroy();
      console.error('Request timeout - connection may be compromised');
    });
    
    // FIX: Handle timeout event
    req.on('timeout', () => {
      req.destroy();
    });
    
    req.on('error', (error) => {
      console.error('Error making Stripe request:', error.message);
    });
    
    // FIX: Send payment data in request body, not in URL
    req.write(requestData);
    req.end();
  }

    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();
