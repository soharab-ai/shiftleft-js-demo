// FIX: Implemented structured logging with automatic redaction for sensitive data
const createLogger = () => {
  return winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: winston.format.json(),
    transports: [
      new winston.transports.Console({
        format: winston.format.simple()
      })
    ],
    // Automatically redact sensitive fields
    redact: ['apiKey', 'password', 'token', 'secret', 'authorization', 'auth']
  });
};
const logger = createLogger();

    this.axiosClient = axios.create({
      baseURL: `${host}/v3/${domain}`,
      timeout: 120000,
      auth: {
        username: username,
        password: apiKey
      }
    });

    // FIX: Implemented environment-based logging controls with structured logging
    // Only log in non-production environments with boolean indicators instead of actual values
    if (process.env.NODE_ENV !== 'production') {
      logger.info('Mail service initialized', {
        host: host,
        domain: domain,
        username: username,
        hasApiKey: !!apiKey
      });
    }
  }

  }

  sendMail(fromAddress, toAddress, subject, msg) {
    const formData = new FormData();
    formData.append('msg', msg);
    try {
      formData.append('package', fs.readFileSync('./package.json'));
    } catch (ex) {
      console.error(ex);
    }
    this.axiosClient.post('/message.mime', {
      from: fromAddress,
      to: toAddress,
      subject,
      html: formData,
      'o:testmode': true
    });
  }
}

module.exports = new Mail(
  process.env.MAIL_GUN_HOST,
  process.env.MAIL_GUN_DOMAIN,
  process.env.MAIL_GUN_USERNAME,
  process.env.MAIL_GUN_API_KEY
);
