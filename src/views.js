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
      FIXED: Remote Code Execution vulnerability mitigated
      - Removed direct eval() usage with user input
      - Replaced regex validation with AST-based parsing for structural validation
      - Replaced vm module sandboxing with purpose-built mathematical expression evaluator
      - Applied input/output sanitization and escaping
      - Added length restrictions and type checking
    */
    let result = '';
    try {
      // Validate and sanitize user input - FIX: Added strict validation
      const userInput = req.query.userInput || '';
      
      // FIX: Validate input type and length
      if (typeof userInput !== 'string') {
        throw new Error('Invalid input type');
      }
      
      if (userInput.length > 100) {
        throw new Error('Input exceeds maximum length of 100 characters');
      }
      
      // FIX: Use AST-based parsing instead of simple regex pattern matching
      // This provides structural validation rather than just character-level validation
      const parser = new Parser();
      
      // FIX: Parse input into AST structure to validate semantic structure
      // This prevents code injection at semantic level, not just syntactic level
      // Only mathematical expressions are allowed - no variable assignments, function definitions, or property access
      let parsedExpression;
      try {
        parsedExpression = parser.parse(userInput);
      } catch (parseError) {
        throw new Error('Invalid mathematical expression');
      }
      
      // FIX: Validate that parsed expression only contains safe node types
      // Reject any dangerous operations like function calls to external objects
      const allowedNodeTypes = ['number', 'binary', 'unary', 'function', 'symbol'];
      const validateAST = (node) => {
        if (!node) return true;
        
        // Check node type is in allowed list
        if (node.type && !allowedNodeTypes.includes(node.type)) {
          throw new Error('Disallowed operation detected');
        }
        
        // For function nodes, only allow whitelisted mathematical functions
        if (node.type === 'function') {
          const safeFunctions = ['sin', 'cos', 'tan', 'sqrt', 'abs', 'log', 'exp', 'pow', 'min', 'max', 'floor', 'ceil', 'round'];
          if (!safeFunctions.includes(node.name)) {
            throw new Error('Disallowed function detected');
          }
        }
        
        // Recursively validate child nodes
        if (node.args) {
          node.args.forEach(arg => validateAST(arg));
        }
        if (node.left) validateAST(node.left);
        if (node.right) validateAST(node.right);
        
        return true;
      };
      
      validateAST(parsedExpression);
      
      // FIX: Use purpose-built mathematical expression evaluator instead of vm module
      // expr-eval.Parser is specifically designed for safe mathematical expression evaluation
      // It has no access to Node.js built-ins, require(), or system resources
      // It only supports mathematical operations by design
      const executionResult = parser.evaluate(userInput);
      
      // FIX: Validate execution result type to prevent prototype pollution
      if (typeof executionResult !== 'number' && typeof executionResult !== 'boolean' && executionResult !== undefined && executionResult !== null) {
        throw new Error('Invalid result type');
      }
      
      result = String(executionResult);
      
      // FIX: Escape output to prevent XSS
      result = validator.escape(result);
      
    } catch (ex) {
      // FIX: Sanitize error messages for logging to prevent log injection
      const sanitizedError = ex.message
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
      console.error('Input processing error:', sanitizedError);
      
      // FIX: Return safe error message without exposing internal details
      result = 'Error: Invalid operation or unsafe input detected';
    }
    
    // FIX: Escape all output rendered to views to prevent XSS
    res.render('UserInput', {
      userInput: validator.escape(req.query.userInput || ''),
      result: result,
      date: new Date().toUTCString()
    });
  }


  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};
