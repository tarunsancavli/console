const jwt = require('jsonwebtoken');

require('dotenv').config();

const authenticateJWT = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(404).json({
      message: "please provide the authorization token"
    })
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
  } catch (err) {
    return res.status(401).json({
      message: "invalid Token"
    })
  }
  return next();

};

module.exports = authenticateJWT;