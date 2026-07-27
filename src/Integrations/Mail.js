// FIX: Implemented structured logging with automatic redaction for sensitive data
const createLogger = () => {
  return winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
constructor(
    host = 'https://api.mailgun.net',
    domain,
    username = 'api',
    apiKey
  ) {
    this.axiosClient = axios.create({
      baseURL: `${host}/v3/${domain}`,
      timeout: 120000,
      auth: {
        username: username,
        password: apiKey
      }
    });
    // FIXED: Implement environment-aware logging - only log in non-production environments
    // Completely removed sensitive apiKey parameter from logging to prevent credential exposure
    if (process.env.NODE_ENV !== 'production') {
      console.log(
        `Connecting to mail host: ${host}:${domain} with username ${username}`
      );
    }
  }

      }
// FIXED: Added centralized secure logging method with automatic sensitive field redaction
// This method systematically sanitizes log output to prevent credential exposure and log injection attacks
logSecure(message, data = {}) {
  // Define sensitive field patterns to automatically redact
  const sensitiveFields = ['apikey', 'password', 'token', 'secret', 'auth', 'authorization', 'credential', 'api_key'];
  
  const sanitizedData = this.sanitizeLogData(data, sensitiveFields);
  
  // Sanitize message to prevent log forging/injection attacks
  const safeMessage = this.sanitizeForLog(message);
  
  // Only log in non-production environments
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[Mail] ${safeMessage}`, JSON.stringify(sanitizedData));
  }
}

    this.axiosClient.post('/message.mime', {
      from: fromAddress,
      to: toAddress,
// FIXED: Helper method to automatically detect and redact sensitive fields based on naming patterns
// Prevents accidental credential exposure through systematic field-level sanitization
sanitizeLogData(obj, sensitiveFields) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  const sanitized = { ...obj };
  for (const key in sanitized) {
    if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
      sanitized[key] = '[REDACTED]';
    }
  }
  return sanitized;
}

// FIXED: Sanitization method to prevent log injection/forging attacks
// Removes control characters and limits message length to prevent log manipulation
sanitizeForLog(input) {
  if (input === null || input === undefined) {
    return '';
  }
  // Remove newlines, carriage returns, and tabs to prevent log forging
  return String(input).replace(/[\n\r\t]/g, ' ').substring(0, 200);
}
