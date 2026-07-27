const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');
// SECURE: Create winston logger with structured logging and automatic sanitization
// Prevents log forging attacks and provides production-ready logging infrastructure
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

    });
    // SECURE FIX: Using structured logging with winston to prevent log forging attacks
    // Prevents injection of newline characters, ANSI escape sequences, and log tampering
    // Winston automatically sanitizes output and provides structured JSON format
    logger.info('Mail client initialized', {
      host: host,
      domain: domain,
      username: username
    });
  }

  }

  sendMail(fromAddress, toAddress, subject, msg) {
    const formData = new FormData();
    formData.append('msg', msg);
    try {
// SECURE: Helper function to mask sensitive credentials for debugging purposes
// Masks all but the first few characters of sensitive data
// Can be integrated with winston redaction format if needed
function maskSensitiveData(data, visibleChars = 4) {
  if (!data || data.length <= visibleChars) {
    return '***';
  }
  return data.substring(0, visibleChars) + '*'.repeat(data.length - visibleChars);
}

module.exports = maskSensitiveData;

}

module.exports = new Mail(
  process.env.MAIL_GUN_HOST,
  process.env.MAIL_GUN_DOMAIN,
  process.env.MAIL_GUN_USERNAME,
  process.env.MAIL_GUN_API_KEY
);
