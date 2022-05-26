const jwt = require('jsonwebtoken')
const { jwt: jwtConfig } = require('../config')
const { AuthenticationError } = require('../errors')

const jwtAuth = async (req, res, next) => {
  const header = req.get('Authorization')
  if (!header) throw new AuthenticationError('No token provided')
  try {
    const token = header.split(' ')[1]
    const decoded = jwt.verify(token, jwtConfig.secret, {
      audience: jwtConfig.audience,
      issuer: jwtConfig.issuer,
    })
    req.user = decoded
    next()
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) next(new AuthenticationError('Invalid token'))
    next(error)
  }
}

module.exports = {
  jwtAuth
}
