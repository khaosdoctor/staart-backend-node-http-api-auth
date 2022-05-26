const { NotFoundError, ValidationError, ConflictError, AuthenticationError, AuthorizationError } = require("../errors")

const validationsToCause = validations =>
  validations.map(({ message, context: { label } }) => ({ message, field: label }))

const responseMappers = {
  UnauthorizedError: (error) => ({
    status: 401,
    body: {
      statusCode: 401,
      error: AuthenticationError.name,
      message: error.message
    }
  }),
  [NotFoundError.name]: (error) => ({
    status: 404,
    body: {
      statusCode: 404,
      error: NotFoundError.name,
      message: error.message,
      cause: [],
    }
  }),
  [AuthenticationError.name]: (error) => ({
    status: 401,
    body: {
      statusCode: 401,
      error: AuthenticationError.name,
      message: error.message,
      cause: error.cause
    }
  }),
  [AuthorizationError.name]: (error) => ({
    status: 403,
    body: {
      statusCode: 403,
      error: AuthorizationError.name,
      message: error.message,
      cause: error.cause
    }
  }),
  [ValidationError.name]: (error) => ({
    status: 400,
    body: {
      statusCode: 400,
      error: ValidationError.name,
      message: error.message,
      cause: validationsToCause(error.validations ?? [])
    }
  }),
  [ConflictError.name]: (error) => ({
    status: 409,
    body: {
      statusCode: 409,
      error: ConflictError.name,
      message: error.message,
      cause: [],
    },
  }),
  default: (error) => ({
    status: 500,
    body: {
      statusCode: 500,
      error: error.name ?? 'UnexpectedError',
      message: error.message,
      cause: [],
    }
  })
}

const errorToResponse = (error) => {
  const mapper = responseMappers[error.name] ?? responseMappers.default
  return mapper(error)
}

const errorHandler = ({ log = console.error } = {}) =>
  (error, _req, res, _next) => {
    log(error)
    const { status, body } = errorToResponse(error)
    res.status(status).send(body)
  }

module.exports = errorHandler
