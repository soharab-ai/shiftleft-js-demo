const secured = require('./Controllers/Secured');

module.exports = app => {
  // Exploits app Env
  app.get('/env', (req, res) => {
    console.log(app.get(req.query.lookup));
    res.send(app.get(req.query.lookup));
  });
  app.get(`/login`, (req, res) => res.render('Login'));

  app.get(`/user-input`, (req, res) => {
(req, res) => {
  /*
    Completely refactored to prevent code injection vulnerability
    Implemented robust input validation, sanitization and structured parameters
  */
  let result = '';
  
  try {
    // Add Content-Security-Policy header for defense-in-depth
    res.setHeader('Content-Security-Policy', "default-src 'self'");

    // Define safe operations that can be performed
    const safeOperations = {
      'add': (a, b) => a + b,
      'subtract': (a, b) => a - b,
      'multiply': (a, b) => a * b,
      'divide': (a, b) => b !== 0 ? a / b : 'Cannot divide by zero',
      'concat': (a, b) => String(a) + String(b),
      'length': (str) => String(str).length
    };

    // Define expected parameter counts for each operation
    const paramCounts = {
      'add': 2,
      'subtract': 2,
      'multiply': 2,
      'divide': 2,
      'concat': 2,
      'length': 1
    };

    // Schema validation for input parameters using Joi
    const schema = Joi.object({
      operation: Joi.string().valid(...Object.keys(safeOperations)).required(),
      params: Joi.array().items(Joi.alternatives().try(
        Joi.string(),
        Joi.number()
      )).required()
    });

    // Validate input against schema
    const { error, value } = schema.validate({
      operation: req.query.operation,
      params: Array.isArray(req.query.params) ? req.query.params : 
              (req.query.params ? [req.query.params] : [])
    });

    if (error) {
      result = `Invalid input: ${error.message}`;
    } else {
      const { operation, params } = value;
      
      // Validate parameter count
      if (params.length !== paramCounts[operation]) {
        result = `Invalid parameter count. Operation '${operation}' requires ${paramCounts[operation]} parameter(s).`;
      } else {
        // Sanitize string parameters to prevent HTML/script injection
        const sanitizedParams = params.map(param => 
          typeof param === 'string' ? purify.sanitize(param) : param
        );
        
        // Execute the operation with validated parameters
        result = util.inspect(safeOperations[operation](...sanitizedParams));
      }
    }
  } catch (ex) {
    console.error('Error processing user input:', ex.message);
    result = 'Error processing input';
  }
  
  // Sanitize user input before rendering to prevent XSS
  const sanitizedUserInput = req.query.operation ? 
    purify.sanitize(req.query.operation) : '';
  
  res.render('UserInput', {
    userInput: sanitizedUserInput,
    result,
    date: new Date().toUTCString()
  });
}

  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};
