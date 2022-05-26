const { knex: Knex } = require('knex')
const { ConflictError, NotFoundError } = require('../../errors')

const { database: config } = require('../../config')

const encodeUser = ({
  username,
  password,
  firstName,
  lastName,
}) => ({
  username,
  password,
  first_name: firstName,
  last_name: lastName,
})

const decodeUser = ({
  id,
  username,
  password,
  first_name,
  last_name,
}) => ({
  id,
  username,
  password,
  firstName: first_name,
  lastName: last_name,
})

const decodeUsers = rows =>
  rows.map(decodeUser)

const handleNotFound = id => ([user]) =>
  user ?? Promise.reject(new NotFoundError({ resourceName: 'user', resourceId: id }))

const handleUniqueUsernameError = username => error =>
  Promise.reject(
    error.code === 'ER_DUP_ENTRY'
      ? new ConflictError(`User with username '${username}' already registered`)
      : error
  )

const SQLRepository = () => {
  const knex = Knex(config)

  const list = () =>
    knex
      .select('*')
      .from('users')
      .then(decodeUsers)

  const get = (id, transaction=knex) =>
    transaction
      .select('*')
      .from('users')
      .where({ id })
      .then(handleNotFound(id))
      .then(decodeUser)

  const getByLogin = (username) => knex
    .select('*')
    .from('users')
    .where({ username })
    .then(handleNotFound(username))
    .then(decodeUser)

  const insert = (user) =>
    // mysql não tem suporte pra INSERT ... RETURNING <props>
    // (INSERT sempre retorna o id do registro criado)
    // então precisamos fazer um select após o INSERT
    knex.transaction(tx =>
      knex('users')
        .insert(encodeUser(user))
        .then(([id]) => get(id, tx))
        .catch(handleUniqueUsernameError(user.username))
    )

  const update = user =>
    // mysql não tem suporte pra UPDATE ... RETURNING <props>
    // (UPDATE sempre retorna a quantidade de registros que foi alterada)
    // então precisamos fazer um select após o UPDATE
    knex.transaction(tx =>
      knex('users')
        .where({ id: user.id })
        .update(encodeUser(user))
        .then(() => get(user.id, tx))
    )

  const del = id =>
    knex('users')
      .where({ id })
      .delete()
      .then()

  return {
    list,
    get,
    insert,
    update,
    del,
    getByLogin
  }

}

module.exports = {
  SQLRepository,
}
