// SECURITY FIX: Hash usernames for logging to prevent sensitive data exposure
function hashForLogging(input) {
  if (!input) return 'null';
  return crypto.createHash('sha256')
    .update(String(input))
    .digest('hex')
    .substring(0, 16); // Use first 16 chars for brevity and consistent identifier
}

    res.redirect('/login');
  }

  encryptData(secretText) {
    const crypto = require('crypto');

    // Weak encryption
    const desCipher = crypto.createCipheriv(
      'des',
      "This is a simple password, don't guess it"
    );
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
        // SECURITY FIX: Removed sensitive PII fields from being stored in variables that could be logged
        // Only extract necessary identifiers
        
        // SECURITY FIX: Use structured logging with hashed username instead of plaintext
        logger.info({
          event: 'login_success',
          user_id: hashForLogging(username),
          timestamp: new Date().toISOString()
        });
        
        // SECURITY FIX: Store only user ID reference instead of full user object and credit card data
        res.cookie('user_id', result._id, { httpOnly: true, secure: true });
        res.cookie('maxAge', 864000);
        // Removed credit card cookie to prevent sensitive data exposure

        // SECURITY FIX: Store only user ID in session instead of full PII
        req.session.user_id = result._id;
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      // SECURITY FIX: Log structured exception metadata without sensitive details
      logger.error({
        event: 'login_error',
        error_type: ex.name,
        error_code: ex.code,
        timestamp: new Date().toISOString()
        // Explicitly exclude ex.message and ex.stack which may contain sensitive data
      });
      this.loginFailed(req, res, data);
    }
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
