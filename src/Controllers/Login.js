const logger = require('../Logger').logger;
const MongoDBClient = require('../DB').MongoDBClient;

class Login {
  loginFailed(req, res, { username, password, keeponline }) {
    res.locals.username = username;
    res.locals.password = password;
    res.locals.keeponline = keeponline;
    res.locals.message = 'Failed to Sign in. Please verify credentials';
    res.redirect('/login');
  }

encryptData(secretText) {
    // Implement secure vault system
    const getEncryptionCredentials = async () => {
      try {
        // Use regular in-memory cache instead of SecureHeap
        if (!this.keyCache) {
          this.keyCache = new Map();
        }

        // Try to get credentials from cache first
        const cachedCredentials = this.keyCache.get('encryptionCredentials');
        if (cachedCredentials && cachedCredentials.expiry > Date.now()) {
          return cachedCredentials.value;
        }

        // If not in cache, fetch from vault system
        const vaultConfig = {
          apiVersion: 'v1',
          endpoint: process.env.VAULT_ENDPOINT || 'http://127.0.0.1:8200',
          token: process.env.VAULT_TOKEN
        };
        
        const vaultClient = vault(vaultConfig);
        const secretResponse = await vaultClient.read('secret/encryption/credentials');
        
        // Fall back to env vars if vault not available
        const masterKey = secretResponse?.data?.masterKey || process.env.MASTER_KEY;
        const salt = secretResponse?.data?.salt || process.env.KEY_SALT;
        const iv = secretResponse?.data?.iv || process.env.ENCRYPTION_IV;
        const keyVersion = secretResponse?.data?.keyVersion || process.env.KEY_VERSION || 'current';
        
        if (!masterKey || !salt || !iv) {
          throw new Error('Encryption credentials not properly configured');
        }
        
        // Implement key derivation using PBKDF2
        const derivedKey = crypto.pbkdf2Sync(
          masterKey, 
          Buffer.from(salt, 'hex'), 
          100000, // 100,000 iterations for security
          32, // 256 bits for AES-256
          'sha256'
        );
        
        const credentials = { 
          key: derivedKey, 
          iv: Buffer.from(iv, 'hex'),
          keyVersion
        };
        
        // Store in memory cache with expiration
        const expiry = Date.now() + 3600000; // Expire after 1 hour
        this.keyCache.set('encryptionCredentials', {
          value: credentials,
          expiry: expiry
        });
        
        return credentials;
      } catch (error) {
        console.error('Error retrieving encryption credentials:', error.message);
        throw new Error('Failed to retrieve encryption credentials');
      }
    };
    
    // Use async/await pattern for vault interaction
    return (async () => {
      try {
        // Get credentials with key rotation support
        const { key, iv, keyVersion } = await getEncryptionCredentials();
        
        // Use a strong authenticated encryption algorithm (AES-256-GCM)
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        
        // Encrypt the data
        let encrypted = cipher.update(secretText, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        // Get authentication tag for verification during decryption
        const authTag = cipher.getAuthTag().toString('hex');
        
        // Include key version for proper decryption during rotation
        return { 
          encrypted, 
          authTag, 
          iv: iv.toString('hex'), 
          keyVersion 
        };
      } catch (error) {
        console.error('Encryption failed:', error.message);
        throw new Error('Failed to encrypt data');
      }
    })();
  }

    return desCipher.write(secretText, 'utf8', 'hex'); // BAD: weak encryption
  }

  async handleLogin(req, res, client, data) {
    const { username, password, keeponline } = data;
    try {
      // DB Query
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      if (!db) {
        this.loginFailed(req, res, data);
        return;
      }
      const result = await db.collection('users').findOne({
        username,
        password
      });
      if (result) {
        const user = {
          fname: result.fname,
          lname: result.lname,
          passportnum: result.passportnum,
          address1: result.address1,
          address2: result.address2,
          zipCode: result.zipCode
        };
        const creditInfo = encryptData(result.creditCard);
        logger.info(`user: ${JSON.stringify(user)} successfully logged in`);
        logger.info(
          `user ${user.fname} credit info: ${JSON.stringify(creditInfo)}`
        );
        res.cookie('username', result.username);
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo);

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }

  login(req, res) {
    /*
      This can be exploited (similar to SQL Injection) when the request body is
      {
        "password": {
          "$gt": ""
        },
        "username": {
          "$gt": ""
        }
      }
    */
    const { username, password, encodedPath, keeponline } = req.body;
    const data = { username, password, keeponline };
    logger.debug(data);
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          this.handleLogin(req, res, client, data);
        } else {
          console.error(err);
          this.loginFailed(req, res, data);
        }
      });
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }
}

module.exports = Login;
