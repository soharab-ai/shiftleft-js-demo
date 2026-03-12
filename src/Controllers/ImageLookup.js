const fs = require("fs");
const { logger } = require("../Logger");

class ImageLookup {
get(req, res) {
  try {
    // Rate limiting implementation - prevents automated enumeration attacks
    const clientId = req.ip || req.connection.remoteAddress;
    if (!this.rateLimiter) {
      this.rateLimiter = new Map();
    }

    const now = Date.now();
    const clientRequests = this.rateLimiter.get(clientId) || { count: 0, resetTime: now + 60000 };

    if (now > clientRequests.resetTime) {
      clientRequests.count = 0;
      clientRequests.resetTime = now + 60000;
    }

    clientRequests.count++;
    this.rateLimiter.set(clientId, clientRequests);

    if (clientRequests.count > 50) { // 50 requests per minute
      logger.warn(`Rate limit exceeded for IP: ${clientId}`);
      return res.status(429).send('Too many requests');
    }

    // Define the base directory for allowed images - restricts file access to specific directory
    const baseDir = path.resolve(__dirname, '../public/images');
    
    // Secure file mapping using allowlist - eliminates directory traversal by design
    const allowedImages = {
      'logo': 'company-logo.png',
      'banner': 'main-banner.jpg',
      'profile': 'default-profile.png',
      'header': 'header-image.png',
      'footer': 'footer-image.jpg',
      'background': 'background.webp',
      'thumbnail': 'thumbnail.png',
      'icon': 'app-icon.svg'
    };
    
    // Get the requested image key from query parameter
    const imageKey = req.query.image;
    
    // Validate input exists and matches allowlist - user input never used in path construction
    if (!imageKey || !allowedImages[imageKey]) {
      return res.status(400).send('Invalid image identifier');
    }
    
    // Map to actual filename from allowlist - prevents arbitrary file access
    const actualFilename = allowedImages[imageKey];
    const requestedPath = path.join(baseDir, actualFilename);
    
    // Normalized boundary validation using path.relative - more robust than startsWith
    const relativePath = path.relative(baseDir, requestedPath);
    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      logger.warn(`Directory traversal attempt detected: ${imageKey.replace(/[\r\n]/g, '')}`);
      return res.status(403).send('Access denied');
    }
    
    // Check if file exists - prevents exposing filesystem structure
    if (!fs.existsSync(requestedPath)) {
      return res.status(404).send('File not found');
    }
    
    // Verify it's a file, not a directory - prevents directory enumeration
    const stats = fs.statSync(requestedPath);
    if (!stats.isFile()) {
      return res.status(400).send('Invalid file');
    }
    
    // Additional validation: check file extension whitelist - restricts to image files only
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'];
    const fileExt = path.extname(requestedPath).toLowerCase();
    if (!allowedExtensions.includes(fileExt)) {
      return res.status(400).send('Invalid file type');
    }
    
    // Set appropriate content type based on extension
    const contentTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.bmp': 'image/bmp',
      '.webp': 'image/webp',
      '.svg': 'image/svg+xml'
    };
    res.setHeader('Content-Type', contentTypes[fileExt] || 'application/octet-stream');
    
    // Use streaming instead of loading entire file - prevents DoS via memory exhaustion
    const readStream = fs.createReadStream(requestedPath);
    readStream.on('error', (streamError) => {
      logger.error(`Error streaming file: ${streamError.message.replace(/[\r\n]/g, '')}`);
      if (!res.headersSent) {
        res.status(500).send('Internal server error');
      }
    });
    logger.info(`Serving image: ${path.basename(requestedPath)}`);
    readStream.pipe(res);
    
  } catch (error) {
    // Generic error handling - prevents information leakage
    logger.error(`Error reading file: ${error.message.replace(/[\r\n]/g, '')}`);
    res.status(500).send('Internal server error');
  }
}

}

module.exports = ImageLookup;
