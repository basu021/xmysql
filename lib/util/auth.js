const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

class Auth {
  constructor(secretKey) {
    this.secretKey = secretKey || process.env.JWT_SECRET || 'xmysql-secret-key';
  }

  // Generate JWT token
  generateToken(user) {
    return jwt.sign(
      { 
        id: user.id,
        username: user.username,
        role: user.role || 'user'
      },
      this.secretKey,
      { expiresIn: '24h' }
    );
  }

  // Verify JWT token
  verifyToken(token) {
    try {
      return jwt.verify(token, this.secretKey);
    } catch (err) {
      return null;
    }
  }

  // Hash password
  async hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  // Compare password
  async comparePassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  // Authentication middleware
  authenticate(req, res, next) {
    // Skip authentication for auth routes
    if (req.path.startsWith('/api/auth/')) {
      return next();
    }

    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = this.verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    req.user = decoded;
    next();
  }
}

module.exports = Auth; 