const fs = require("fs");
const { logger } = require("../Logger");

class ImageLookup {
get(req, res) {
  try {
    // Define a secure base directory where images should be located
    const IMAGES_DIR = path.resolve(__dirname, '../images');
    
    // Sanitize and validate the input filename
    const filename = req.query.image;
    
    // Added: More comprehensive regex pattern validation for filenames
    if (!filename || !filename.match(/^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif)$/)) {
      return res.status(400).send('Invalid image name format');
    }
    
    // Added: Implement filename whitelisting from configuration
    const validFilenames = ['image1.jpg', 'image2.png', 'image3.gif']; // Could be loaded from configuration
    if (!validFilenames.includes(filename)) {
      return res.status(400).send('Invalid image name');
    }
    
    // Resolve the full path and ensure it's within the allowed directory
    const imagePath = path.join(IMAGES_DIR, filename);
    
    // Added: Improved path validation using normalize
    const normalizedPath = path.normalize(imagePath);
    if (normalizedPath !== imagePath || !normalizedPath.startsWith(IMAGES_DIR)) {
      return res.status(403).send('Access denied');
    }
    
    // Added: Content-Type verification to ensure only image files are served
    const mimeType = mime.lookup(imagePath);
    if (!mimeType || !mimeType.startsWith('image/')) {
      return res.status(403).send('Invalid file type');
    }
    
    // Added: Use streams instead of synchronous reading
    logger.debug(`Serving image: ${filename}`);
    fs.createReadStream(imagePath)
      .on('error', (err) => {
        logger.error(`Error reading image: ${filename}`);
        res.status(404).send('Image not found');
      })
      .pipe(res);
      
  } catch (error) {
    logger.error(`Error processing image request: ${error.message}`);
    res.status(404).send('Image not found');
  }
}

}

module.exports = ImageLookup;
