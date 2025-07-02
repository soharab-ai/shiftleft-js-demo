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
encryptData(secretText, userPassword = null) {
    try {
        // FIXED: Implemented proper key management using a KDF (PBKDF2)
        // Either use user password or a secure application master key
        const salt = crypto.randomBytes(16);
        
        // FIXED: Derive key from password using PBKDF2 instead of returning raw key
        let key;
        if (userPassword) {
            // Generate key from user password if provided
            key = crypto.pbkdf2Sync(userPassword, salt, 100000, 32, 'sha512');
        } else {
            // Use application master key with KDF
            // FIXED: Master key should be stored in environment variables or secure vault
            const masterKey = process.env.MASTER_ENCRYPTION_KEY || config.getMasterKey();
            key = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha512');
        }
        
        const iv = crypto.randomBytes(16); // 128 bits for GCM mode
        
        // FIXED: Used modern encryption algorithm with proper parameters
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        
        let encrypted = cipher.update(secretText, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        // FIXED: Store key version for future algorithm changes and key rotation
        const keyVersion = config.getCurrentKeyVersion();
        
        // FIXED: Never return the actual encryption key
        return {
            encryptedData: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            salt: salt.toString('hex'),
            keyVersion: keyVersion,
            algorithm: 'aes-256-gcm'
        };
    } catch (error) {
        // FIXED: Added proper error handling to prevent information leakage
        console.error('Encryption error occurred');
        throw new Error('Failed to encrypt data. Please try again later.');
    }
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
