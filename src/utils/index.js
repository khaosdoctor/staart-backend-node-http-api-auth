const { createHash } = require('crypto')

const wait = (time) =>
  new Promise(resolve =>
    setTimeout(resolve, time)
  )

const encrypt = async (data) => createHash('sha512').update(data).digest('hex')

module.exports = {
  wait,
  encrypt
}
