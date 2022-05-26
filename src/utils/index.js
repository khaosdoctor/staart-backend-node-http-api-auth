const { createHash, timingSafeEqual } = require('crypto')

const wait = (time) =>
  new Promise(resolve =>
    setTimeout(resolve, time)
  )

const encrypt = async (data) => createHash('sha512').update(data).digest('hex')

const safeCompare = async (data, comparison) => timingSafeEqual(Buffer.from(data), Buffer.from(comparison))

module.exports = {
  wait,
  encrypt,
  safeCompare
}
