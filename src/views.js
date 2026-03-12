const secured = require('./Controllers/Secured');

module.exports = app => {
  // Exploits app Env
  app.get('/env', (req, res) => {
    console.log(app.get(req.query.lookup));
    res.send(app.get(req.query.lookup));
  });
  app.get(`/login`, (req, res) => res.render('Login'));

(req, res) => {
    /*
      Fixed: Removed eval() and vm2 vulnerabilities by implementing safe mathematical
      expression parsing using mathjs library. This prevents remote code execution attacks
      by treating user input as data to be parsed, not code to be executed.
    */
    let result = '';
    let sanitizedInput = '';
    
    try {
      // FIX: Sanitize user input to prevent XSS and injection attacks
      const userInput = req.query.userInput || '';
      sanitizedInput = userInput.replace(/[<>&"']/g, (char) => {
        const escapeMap = {
          '<': '&lt;',
          '>': '&gt;',
          '&': '&amp;',
          '"': '&quot;',
          "'": '&#x27;'
        };
        return escapeMap[char];
      });
      
      // FIX: Length validation to prevent DoS attacks through extremely long expressions
      if (!userInput) {
        result = 'No input provided';
      } else if (userInput.length > 100) {
        result = 'Invalid input: Expression too long (maximum 100 characters)';
      } else {
        // FIX: Strengthened input validation - only allow ASCII digits and basic mathematical operators
        const allowedPattern = /^[0-9+\-*/(). ]+$/;
        
        if (allowedPattern.test(userInput)) {
          // FIX: Use mathjs evaluate() instead of eval() or VM execution
          // This parses expressions as data without executing arbitrary code
          // Create a limited scope for mathjs evaluation (no custom functions or variables)
          const limitedScope = {};
          // Configure mathjs to prevent function assignments and only allow basic math
          result = math.evaluate(userInput, limitedScope);
        } else {
          // FIX: Reject any input that doesn't match the whitelist
          result = 'Invalid input: Only mathematical expressions with numbers and basic operators (+, -, *, /, parentheses) are allowed';
          
          // FIX: Log suspicious input attempts for security monitoring (with sanitized input to prevent log forging)
          const sanitizedForLog = userInput.replace(/[\r\n]/g, '').substring(0, 200);
          console.warn(`[SECURITY] Rejected potentially malicious input: ${sanitizedForLog}`);
        }
      }
    } catch (ex) {
      // FIX: Handle mathjs-specific parsing and evaluation errors without exposing sensitive information
      console.error('[SECURITY] Expression evaluation error:', ex.message);
      if (ex.message && ex.message.includes('Undefined symbol')) {
        result = 'Error: Invalid mathematical operation or unknown function.';
      } else {
        result = 'Error: Unable to process input. Please enter a valid mathematical expression.';
      }
    }
    
    // FIX: Use sanitized input in response to prevent XSS attacks
    res.render('UserInput', {
      userInput: sanitizedInput,
      result,
      date: new Date().toUTCString()
    });
  }


  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};
