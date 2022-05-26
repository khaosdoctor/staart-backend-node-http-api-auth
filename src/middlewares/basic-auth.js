const { AuthenticationError, NotFoundError } = require('../errors')
const { encrypt, safeCompare } = require('../utils')

const decriptHeader = async (authorizationHeader) => {
  // O formato do header é: Basic <base64>
  // Depois de quebrado será ['Basic', '<base64>']
  if (!authorizationHeader) throw new AuthenticationError(null, 'Header not found')
  const [type, credentials] = authorizationHeader.split(' ')
  if (type !== 'Basic') throw new AuthenticationError(null, 'Header type mismatch')

  const decriptedCredentials = Buffer
    .from(credentials, 'base64')
    .toString('utf-8')

  const [username, plainPassword] = decriptedCredentials.split(':')
  return {
    username,
    plainPassword
  }
}

const basicAuth = repository => async (req, res, next) => {
  try {
    const basicHeader = req.get('Authorization')
    const { username, plainPassword } = await decriptHeader(basicHeader)
    if (!username || !plainPassword) throw new AuthenticationError(null, 'Missing data')

    const user = await repository.getByLogin(username)
    const isValid = await safeCompare(await encrypt(plainPassword), user.password)
    if (!isValid) throw new AuthenticationError(username, 'Invalid credentials')

    req.user = user
    next()
  } catch (error) {
    // O ideal aqui é não dizer que o usuário não foi encontrado
    // Mas sim que as credenciais estão erradas
    if (error instanceof NotFoundError) next(new AuthenticationError(error.resourceId, 'Username not found'))
    next(error)
  }
}

module.exports = { basicAuth }
