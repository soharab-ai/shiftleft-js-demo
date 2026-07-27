// SECURITY FIX: Added express-validator middleware chain for input validation
const validateUserInput = [
  query('userInput')
    .trim()
    .isLength({ max: 200 })
    .withMessage('Input must not exceed 200 characters')
    .matches(/^[0-9+\-*/().,\s]+$/)
    .withMessage('Only numbers and basic mathematical operators allowed')
    .escape()
];

// SECURITY FIX: Added CSP headers for defense-in-depth
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // SECURITY FIX: Validate request using express-validator middleware
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('UserInput', {
      userInput: '',
      result: 'Invalid input provided',
      date: new Date().toUTCString()
    });
  }

  (req, res) => {
    /*
      FIXED: Removed eval() vulnerability - replaced with safe math expression parser
      Now uses mathjs library with compile() method for maximum security
      Implements strict input validation and sanitization
    */
    let result = '';
    let userInput = req.query.userInput || '';
    
    // SECURITY FIX: Sanitize input to prevent log injection
    const sanitizedInput = userInput.replace(/[\r\n\t]/g, ' ').substring(0, 200);
    
    // SECURITY FIX: Validate input length to prevent abuse
    if (sanitizedInput.length === 0) {
      result = 'No input provided';
    } else if (sanitizedInput.length > 200) {
      result = 'Input too long - maximum 200 characters allowed';
    } else {
      try {
        // SECURITY FIX: Strengthened regex pattern with negative lookahead to block dangerous function names
        // Removed alphabetic character support to prevent function calls
        const allowedPattern = /^(?!.*(import|createUnit|parse|compile|eval|Function|constructor))[0-9+\-*/().,\s]+$/i;
        
        if (!allowedPattern.test(sanitizedInput)) {
          result = 'Invalid input - only numbers and basic operators allowed';
        } else {
          // SECURITY FIX: Use mathjs.compile() with empty scope instead of evaluate()
          // This prevents access to JavaScript prototypes and external functions
          const limitedScope = {}; // Empty scope prevents access to any external functions
          const compiled = mathjs.compile(sanitizedInput);
          const evaluatedResult = compiled.evaluate(limitedScope);
          result = require('util').inspect(evaluatedResult);
        }
      } catch (ex) {
        // SECURITY FIX: Don't expose internal error details
        result = 'Error: Unable to evaluate expression. Please check syntax.';
        // SECURITY FIX: Sanitize error logging to prevent log injection
        console.error('Math evaluation error for input:', sanitizedInput.substring(0, 50), 'Error:', ex.message);
      }
    }
    
    // SECURITY FIX: Implement output encoding to prevent template injection
    res.render('UserInput', {
      userInput: he.encode(sanitizedInput),
      result: he.encode(String(result)),
      date: new Date().toUTCString()
    });
  }


  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};
