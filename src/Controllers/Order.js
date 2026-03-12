// FIX: Initialize structured logging with sanitization for audit trails
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'audit.log', level: 'info' }),
    new winston.transports.File({ filename: 'error.log', level: 'error' })
  ]
});

// FIX: Initialize AWS Secrets Manager client for secure credential retrieval
const secretsManager = new AWS.SecretsManager({
  region: process.env.AWS_REGION || 'us-east-1'
});

// FIX: Sanitize log entries to prevent log injection attacks
function sanitizeLogEntry(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/[\n\r]/g, ' ').replace(/[^\x20-\x7E]/g, '');
}

    }
// FIX: Implement secure secrets retrieval from AWS Secrets Manager with retry logic
async function getSecretWithRetry(secretName, maxRetries = 3) {
  let retries = 0;
  let delay = 1000;

  while (retries < maxRetries) {
    try {
      const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
      
      if (data.SecretString) {
        return JSON.parse(data.SecretString);
      } else {
        const buff = Buffer.from(data.SecretBinary, 'base64');
        return JSON.parse(buff.toString('ascii'));
      }
    } catch (error) {
      retries++;
      if (retries >= maxRetries) {
        logger.error('Failed to retrieve secret after maximum retries', {
          secretName: sanitizeLogEntry(secretName),
          error: error.message
        });
        throw new Error('Failed to retrieve credentials from secrets manager');
      }
      // FIX: Exponential backoff for retry logic
      await new Promise(resolve => setTimeout(resolve, delay));
      delay *= 2;
    }
  }
}

// FIX: Validate encryption key format (64 hex characters for AES-256)
function validateEncryptionKey(key) {
  const hexPattern = /^[0-9a-f]{64}$/i;
  if (!key || !hexPattern.test(key)) {
    throw new Error('Invalid encryption key format. Expected 64 hexadecimal characters.');
  }
  return true;
}

// FIX: Validate Stripe API key format
function validateStripeKey(key) {
  if (!key || (!key.startsWith('sk_test_') && !key.startsWith('sk_live_'))) {
    throw new Error('Invalid Stripe API key format');
  }
  return true;
}

        timestamp: new Date().toISOString(),
        operation: 'getStripeCredentials',
        sessionId: sanitizeLogEntry(sessionId || 'unknown'),
        environment: process.env.NODE_ENV || 'unknown'
      });
      
      // FIX: Update cache
      this.credentialCache.stripeKey = stripeKey;
      this.credentialCache.stripeKeyTimestamp = now;
      
      return stripeKey;
    } catch (error) {
      logger.error('Failed to retrieve Stripe credentials', {
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw new Error('Credential retrieval failed');
    }
  }

  // FIX: Clear sensitive data from memory after use
  clearKeyFromMemory(keyBuffer) {
    if (Buffer.isBuffer(keyBuffer)) {
      keyBuffer.fill(0);
    }
  }

  hex(key) {
    return key;
  }

  // FIX: Updated encryption with AES-256-GCM and secure key retrieval
  async encryptData(secretText, sessionId) {
    try {
      // FIX: Retrieve encryption key securely with audit logging
      const encryptionKey = await this.getEncryptionKey();
      
      const algorithm = 'aes-256-gcm';
      const key = Buffer.from(encryptionKey, 'hex');
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      let encrypted = cipher.update(secretText, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      
      // FIX: Clear sensitive key data from memory
      this.clearKeyFromMemory(key);
      
      // FIX: Audit log for encryption operation
      logger.info('Data encrypted', {
        timestamp: new Date().toISOString(),
        operation: 'encryptData',
        sessionId: sanitizeLogEntry(sessionId || 'unknown')
      });
      
      return JSON.stringify({
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      });
    } catch (error) {
      logger.error('Encryption failed', {
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  // FIX: Updated decryption with AES-256-GCM and secure key retrieval
  async decryptData(encryptedData, sessionId) {
    try {
      // FIX: Retrieve encryption key securely
      const encryptionKey = await this.getEncryptionKey();
      
      const algorithm = 'aes-256-gcm';
      const key = Buffer.from(encryptionKey, 'hex');
      const data = JSON.parse(encryptedData);
      
      const decipher = crypto.createDecipheriv(
        algorithm,
        key,
        Buffer.from(data.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
      
      let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      // FIX: Clear sensitive key data from memory
      this.clearKeyFromMemory(key);
      
      return decrypted;
    } catch (error) {
      logger.error('Decryption failed', {
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  async addToOrder(req, res) {
    const order = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(await this.decryptData(req.session.orders, req.session.id));
      order.id = crypto.randomBytes(256).toString('hex');
      orders.push(order);
      req.session.orders = await this.encryptData(JSON.stringify(orders), req.session.id);
    }
    res.send(200);
  }

  async removeOrder(req, res) {
    const { orderId } = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(await this.decryptData(req.session.orders, req.session.id));
      const newOrders = orders.filter(order => orderId !== order.orderId);
      req.session.orders = await this.encryptData(JSON.stringify(newOrders), req.session.id);
      console.log(newOrders);
    }
    res.send(200);
  }

  async checkout(req, res) {
    if (req.session.orders) {
      const orders = JSON.parse(await this.decryptData(req.session.orders, req.session.id));
      let totalPrice = 0;
      for (let index = 0; index < orders.length; index += 1) {
        totalPrice += orders[index].price;
      }
      await this.processCC(req, res, orders, totalPrice);
    }
    console.log(req.session.orders);
  }

  // FIX: Implement secure Stripe request with credential retrieval from secrets manager
  async createStripeRequest(creditCard, price, address, sessionId) {
    try {
      // FIX: Retrieve restricted Stripe credentials with audit logging
      const STRIPE_RESTRICTED_KEY = await this.getStripeCredentials(sessionId);
      
      // FIX: Generate idempotency key to prevent duplicate charges
      const idempotencyKey = crypto.randomBytes(16).toString('hex');
      
      // FIX: Use proper HTTPS API endpoint with Authorization header
      const options = {
        hostname: 'api.stripe.com',
        port: 443,
        path: '/v1/charges',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${STRIPE_RESTRICTED_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Idempotency-Key': idempotencyKey
        }
      };
      
      // FIX: Format request data with metadata for audit trail
      const postData = querystring.stringify({
        amount: price,
        currency: 'usd',
        source: creditCard,
        description: 'Order payment',
        metadata: {
          application: 'tarpit',
          sessionId: sessionId || 'unknown',
          idempotencyKey: idempotencyKey
        }
      });
      
      // FIX: Audit log for payment processing attempt
      logger.info('Stripe payment initiated', {
        timestamp: new Date().toISOString(),
        operation: 'createStripeRequest',
        sessionId: sanitizeLogEntry(sessionId || 'unknown'),
        amount: price,
        idempotencyKey: idempotencyKey
      });
      
      // FIX: Implement secure HTTPS request with proper error handling
      const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          logger.info('Stripe payment processed', {
            timestamp: new Date().toISOString(),
            statusCode: res.statusCode,
            idempotencyKey: idempotencyKey
          });
        });
      });
      
      req.on('error', (error) => {
        logger.error('Error processing Stripe payment', {
          error: error.message,
          timestamp: new Date().toISOString(),
          idempotencyKey: idempotencyKey
        });
      });
// FIX: Implement startup health check to validate credentials and encryption functionality
async function performStartupHealthCheck() {
  try {
    logger.info('Starting credential health check', {
      timestamp: new Date().toISOString()
    });

    // FIX: Test encryption key retrieval and validation
    const testOrder = new Order();
    const encryptionKey = await testOrder.getEncryptionKey();
    
    // FIX: Perform test encryption/decryption to verify key works
    const testData = 'health-check-test';
    const encrypted = await testOrder.encryptData(testData, 'health-check');
    const decrypted = await testOrder.decryptData(encrypted, 'health-check');
    
    if (decrypted !== testData) {
      throw new Error('Encryption health check failed: decrypted data does not match original');
    }

    // FIX: Test Stripe credentials retrieval and validation
    const stripeKey = await testOrder.getStripeCredentials('health-check');
    
    logger.info('Credential health check completed successfully', {
      timestamp: new Date().toISOString(),
      encryptionKeyValid: true,
      stripeKeyValid: true
    });

    return true;
  } catch (error) {
    logger.error('Credential health check failed', {
      error: error.message,
      timestamp: new Date().toISOString()
    });
    // FIX: Fail fast if credentials are invalid
    throw new Error('Application startup failed: Invalid credentials configuration');
  }
}

// FIX: Execute health check on module load
performStartupHealthCheck().catch(error => {
  console.error('Fatal: Application cannot start due to credential validation failure');
  process.exit(1);
});

          await db.collection('transactions').insertOne(transaction);
          
          // FIX: Call secure Stripe request with session context
          await self.createStripeRequest(
            result.creditCard,
            totalPrice,
            transaction.billingAddress,
            req.session.id
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

