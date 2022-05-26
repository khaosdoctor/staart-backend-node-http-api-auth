const { jwt: jwtConfig } = require('../config')
const { expressjwt } = require('express-jwt')

module.exports = {
  jwtAuth: expressjwt({
    secret: jwtConfig.secret,
    audience: jwtConfig.audience,
    issuer: jwtConfig.issuer,
    algorithms: ['HS256'],
  }),
}
