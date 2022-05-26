const { Router } = require('express')
const Joi = require('joi')

const withAsyncErrorHandler = require('../middlewares/async-error')
const { basicAuth } = require('../middlewares/basic-auth')
const validate = require('../middlewares/validate')
const { encrypt } = require('../utils')

const { UsersRepository } = require('./repository')

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
  const body = req.body
  const registered = await repository.get(id)
  const user = { ...registered, ...body, id }
  const updated = await repository.update(user)
  res.status(200).send(updated)
}

router.put('/:id', basicAuth(repository), validate(UpdateUserSchema), withAsyncErrorHandler(updateUser))

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
  await repository.get(id)
  await repository.del(id)
  res.status(204).send()
}

router.delete('/:id', basicAuth(repository), validate(DeleteUserSchema), withAsyncErrorHandler(deleteUser))

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
router.get('/:id', basicAuth(repository), validate(GetUserSchema), withAsyncErrorHandler(getUser))

module.exports = router
