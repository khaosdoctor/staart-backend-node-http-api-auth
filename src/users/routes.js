const { Router } = require('express')
const Joi = require('joi')
const jwt = require('jsonwebtoken')

const withAsyncErrorHandler = require('../middlewares/async-error')
const { jwtAuth } = require('../middlewares/jwt-auth')
const validate = require('../middlewares/validate')
const { encrypt, safeCompare } = require('../utils')
const { jwt: jwtConfig } = require('../config')
const { UsersRepository } = require('./repository')
const { NotFoundError, AuthenticationError, AuthorizationError } = require('../errors')

const NameRegex = /^[A-Z][a-z]+$/

const router = Router()
const repository = UsersRepository()

/*
  CRUD de usuários
  - C: create
  - R: read (listar + detalhes)
  - U: update
  - D: delete
*/

// ************
// ** create **
// ************

const CreateUserBodySchema = {
  body: Joi.object({
    username: Joi.string().email().required(),
    password: Joi.string().min(5).max(255).required(),
    firstName: Joi.string().regex(NameRegex).required(),
    lastName: Joi.string().regex(NameRegex).required(),
  })
}

const createUser = async (req, res) => {
  const user = { ...req.body, password: await encrypt(req.body.password) }
  const { password, ...inserted } = await repository.insert(user)
  const location = `/api/users/${inserted.id}`
  res.status(201).header('Location', location).send(inserted)
}

router.post('/', validate(CreateUserBodySchema), withAsyncErrorHandler(createUser))

// ************
// ** update **
// ************

const UpdateUserSchema = {
  params: Joi.object({
    id: Joi.number().required(),
  }),
  body: Joi.object({
    password: Joi.string().min(5).max(255),
    firstName: Joi.string().regex(NameRegex),
    lastName: Joi.string().regex(NameRegex),
  }).or('password', 'firstName', 'lastName')
}

const updateUser = async (req, res) => {
  const id = parseInt(req.params.id)
  if (id !== req.auth.id) throw new AuthorizationError('You are not authorized to update this user')
  const body = req.body
  const registered = await repository.get(id)
  const user = { ...registered, ...body, id }
  const updated = await repository.update(user)
  res.status(200).send(updated)
}

router.put('/:id', jwtAuth, validate(UpdateUserSchema), withAsyncErrorHandler(updateUser))

// ************
// ** delete **
// ************

const DeleteUserSchema = {
  params: Joi.object({
    id: Joi.number().required(),
  })
}

const deleteUser = async (req, res) => {
  const id = parseInt(req.params.id)
  if (id !== req.auth.id) throw new AuthorizationError('You are not authorized to delete this user')
  await repository.get(id)
  await repository.del(id)
  res.status(204).send()
}

router.delete('/:id', jwtAuth, validate(DeleteUserSchema), withAsyncErrorHandler(deleteUser))

// **********
// ** read **
// **********

const GetUserSchema = {
  params: Joi.object({
    id: Joi.number().required(),
  })
}

const listUsers = (_req, res) =>
  repository
    .list()
    .then(users => res.status(200).send({ users }))

const getUser = async (req, res) => {
  const id = parseInt(req.params.id)
  const user = await repository.get(id)
  res.status(200).send(user)
}

router.get('/', withAsyncErrorHandler(listUsers))
router.get('/:id', jwtAuth, validate(GetUserSchema), withAsyncErrorHandler(getUser))

// **********
// ** login **
// **********

const LoginUserSchema = {
  body: Joi.object({
    username: Joi.string().email().required(),
    password: Joi.string().min(5).max(255).required(),
  })
}

const loginUser = async (req, res) => {
  const { username, password } = req.body
  try {
    const { password: userPassword, ...user } = await repository.getByLogin(username)

    const encrypted = await encrypt(password)
    console.log({ username, password, userPassword, encrypted })
    const isValid = await safeCompare(encrypted, userPassword)
    if (!isValid) throw new AuthenticationError('Invalid credentials')

    const token = jwt.sign(user, jwtConfig.secret, {
      expiresIn: jwtConfig.expiration,
      audience: jwtConfig.audience,
      issuer: jwtConfig.issuer
    })
    res.status(200).send({ token })
  } catch (err) {
    if (err instanceof NotFoundError) throw new AuthenticationError('Invalid credentials')
  }
}

router.post('/login', validate(LoginUserSchema), withAsyncErrorHandler(loginUser))

module.exports = router
