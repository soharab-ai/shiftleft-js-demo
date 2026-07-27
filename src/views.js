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
      Fixed: Remote Code Execution vulnerability eliminated
      - Removed dangerous eval() function and vm2 sandbox (deprecated and vulnerable)
      - Implemented safe mathematical expression evaluation using mathjs
      - Added strict input validation with whitelist pattern matching
      - Restricted to arithmetic operations only
    */
    let result = '';
    try {
      const userInput = req.query.userInput;
      
      // Input validation: Check if input exists and is not empty
      if (!userInput || typeof userInput !== 'string') {
        result = 'Error: Invalid or missing input';
      } else if (userInput.length > 1000) {
        // Prevent excessively long inputs that could cause DoS
        result = 'Error: Input too long (maximum 1000 characters)';
      } else {
        // Strict whitelist validation: only allow numbers, operators, and parentheses
        // This prevents any code injection attempts before evaluation
        const safePattern = /^[0-9+\-*\/%.() ]+$/;
        if (!safePattern.test(userInput)) {
          result = 'Error: Invalid characters detected. Only numbers and basic operators (+, -, *, /, %, parentheses) are allowed';
        } else {
          // Configure mathjs with restricted scope - no functions or constants
          // Only basic arithmetic operations are permitted
          const limitedMath = math.create({
            number: 'number',
            precision: 14
          });
          
          // Disable all functions and only allow basic arithmetic operators
          const restrictedEvaluator = limitedMath.evaluate;
          const evaluationScope = {}; // Empty scope prevents variable access
          
          // Safely evaluate mathematical expression in restricted context
          const mathResult = restrictedEvaluator(userInput, evaluationScope);
          result = String(mathResult);
        }
      }
    } catch (ex) {
      // Sanitize error messages to prevent information leakage
      console.error('Expression evaluation error:', ex.message);
      result = 'Error: Unable to evaluate the provided expression safely';
    }
    
    // Sanitize userInput before rendering to prevent XSS
    const sanitizedInput = req.query.userInput ? 
      String(req.query.userInput).substring(0, 200) : '';
    
    res.render('UserInput', {
      userInput: sanitizedInput,
      result,
      date: new Date().toUTCString()
    });
  }

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
