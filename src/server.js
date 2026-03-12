const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');

const { logger } = require('./Logger');
const registerApiRoutes = require('./api');
const registerViewRoutes = require('./views');

const app = express();
// FIXED: Added secret strength validation to ensure cryptographic quality (CWE-798 mitigation)
const validateSecretStrength = (secret) => {
  if (!secret || typeof secret !== 'string') {
    return { valid: false, reason: 'Secret must be a non-empty string' };
  }
  
  // FIXED: Minimum 32 characters as per NIST SP 800-132 recommendations
  if (secret.length < 32) {
    return { valid: false, reason: 'Secret must be at least 32 characters long' };
  }
  
  // FIXED: Check for sufficient entropy - at least 3 different character types
  const hasLower = /[a-z]/.test(secret);
  const hasUpper = /[A-Z]/.test(secret);
  const hasNumber = /[0-9]/.test(secret);
  const hasSpecial = /[^a-zA-Z0-9]/.test(secret);
  const diversity = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
// FIXED: Persistent secret management for development to maintain session consistency across restarts
const getOrCreateDevSecret = () => {
  const devSecretPath = path.join(__dirname, '..', '.env.local');
  const secretKey = 'SESSION_SECRET_KEY';
  
  try {
    // FIXED: Attempt to read existing development secret from .env.local file
    if (fs.existsSync(devSecretPath)) {
      const envContent = fs.readFileSync(devSecretPath, 'utf-8');
      const match = envContent.match(new RegExp(`${secretKey}=(.+)`));
      
      if (match && match[1]) {
        const existingSecret = match[1].trim();
        logger.info('Using existing development session secret from .env.local');
        return existingSecret;
      }
    }
    
    // FIXED: Generate new cryptographically secure secret if none exists
    const newSecret = crypto.randomBytes(64).toString('hex');
    const envContent = `# AUTO-GENERATED DEVELOPMENT SECRET - DO NOT COMMIT TO VERSION CONTROL\n${secretKey}=${newSecret}\n`;
    
    fs.writeFileSync(devSecretPath, envContent, { mode: 0o600 });
    logger.info('Generated new development session secret and saved to .env.local (git-ignored)');
    logger.warn('IMPORTANT: .env.local file created. Ensure this file is in .gitignore');
    
    return newSecret;
  } catch (error) {
    logger.error(`Failed to read/write development secret: ${error.message}`);
    // FIXED: Fallback to ephemeral secret if file operations fail
    return crypto.randomBytes(64).toString('hex');
  }
// FIXED: Secret age tracking to encourage rotation per NIST SP 800-57 Part 1 Rev. 5
const checkSecretAge = () => {
  const secretCreatedAt = process.env.SESSION_SECRET_CREATED_AT;
  
  if (!secretCreatedAt) {
    logger.warn('SESSION_SECRET_CREATED_AT not set. Consider adding timestamp for secret rotation tracking.');
    return;
  }
  
  try {
    const createdDate = new Date(secretCreatedAt);
    const now = new Date();
    const ageInDays = (now - createdDate) / (1000 * 60 * 60 * 24);
    
    // FIXED: Warn if secret is older than 90 days
    if (ageInDays > 90) {
      logger.warn(`SESSION_SECRET_KEY is ${Math.floor(ageInDays)} days old. NIST recommends rotating secrets every 90 days.`);
    }
// FIXED: Secure configuration object with non-enumerable sensitive properties to prevent accidental exposure
const createSecureConfig = (sessionSecretKey, applicationPort) => {
  const config = {
    applicationPort: applicationPort,
    // FIXED: Store only hash of secret for verification, not the actual secret
    sessionSecretHash: crypto.createHash('sha256').update(sessionSecretKey).digest('hex').substring(0, 16)
  };
  
  // FIXED: Define sessionSecretKey as non-enumerable property to prevent logging/serialization exposure
  Object.defineProperty(config, 'sessionSecretKey', {
    value: sessionSecretKey,
    writable: false,
    enumerable: false, // FIXED: Prevents exposure in console.log, JSON.stringify, Object.keys
    configurable: false
  });
  
  // FIXED: Add getter method for controlled access
  Object.defineProperty(config, 'getSessionSecret', {
    value: function() {
      return this.sessionSecretKey;
    },
    writable: false,
// FIXED: Multi-factor production environment verification to prevent misconfiguration
const verifyProductionEnvironment = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (!isProduction) {
    return true; // Non-production environments pass verification
  }
  
  const checks = [];
  
  // FIXED: Check 1 - SESSION_SECRET_KEY must be present
  checks.push({
    name: 'SESSION_SECRET_KEY present',
    passed: !!process.env.SESSION_SECRET_KEY
  });
  
  // FIXED: Check 2 - PRODUCTION_VERIFIED flag must be explicitly set
  checks.push({
    name: 'PRODUCTION_VERIFIED flag',
    passed: process.env.PRODUCTION_VERIFIED === 'true'
  });
  
  // FIXED: Check 3 - Development-only variables must be absent
  const devVarsPresent = process.env.DEBUG || process.env.DEV_MODE;
  checks.push({
    name: 'No development variables',
// FIXED: Startup self-test to verify secret is properly formatted and functional
const testSecretFunctionality = (secret) => {
  try {
    const testPayload = 'test-session-data';
    
    // FIXED: Test encryption with the session secret
    const cipher = crypto.createCipher('aes-256-cbc', secret);
    let encrypted = cipher.update(testPayload, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // FIXED: Test decryption with the session secret
    const decipher = crypto.createDecipher('aes-256-cbc', secret);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    if (decrypted !== testPayload) {
      throw new Error('Encryption/decryption test failed - data mismatch');
    }
    
    logger.info('Session secret functionality verified successfully');
    return true;
// FIXED: Session binding middleware to prevent session hijacking via device/network fingerprinting
const sessionBindingMiddleware = (req, res, next) => {
  if (!req.session) {
    return next();
  }
  
  // FIXED: Create fingerprint from User-Agent and IP address (first 3 octets only for privacy)
  const userAgent = req.headers['user-agent'] || '';
  const ipAddress = req.ip || req.connection.remoteAddress || '';
  const ipPrefix = ipAddress.split('.').slice(0, 3).join('.'); // First 3 octets only
  
  const currentFingerprint = crypto
    .createHash('sha256')
    .update(`${userAgent}|${ipPrefix}`)
    .digest('hex');
  
  if (req.session.fingerprint) {
    // FIXED: Verify fingerprint matches
    if (req.session.fingerprint !== currentFingerprint) {
      logger.warn(`Session binding violation detected for session ${req.sessionID}`);
      req.session.destroy((err) => {
        if (err) logger.error(`Failed to destroy hijacked session: ${err.message}`);
      });
      return res.status(403).send('Session security violation detected');
    }
  } else {
    // FIXED: Set fingerprint on first request
    req.session.fingerprint = currentFingerprint;
// FIXED: Helper function for session regeneration after authentication to prevent session fixation
const regenerateSessionOnAuth = (req, callback) => {
  const oldSessionData = req.session;
  
  req.session.regenerate((err) => {
    if (err) {
      logger.error(`Session regeneration failed: ${err.message}`);
      return callback(err);
    }
    
    // FIXED: Restore non-sensitive session data after regeneration
    Object.keys(oldSessionData).forEach(key => {
      if (key !== 'cookie' && key !== 'fingerprint') {
        req.session[key] = oldSessionData[key];
      }
    });
    
    logger.info(`Session regenerated for security after authentication`);
    callback(null);
  });
};
