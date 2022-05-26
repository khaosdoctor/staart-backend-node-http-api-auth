const { timingSafeEqual, pbkdf2Sync } = require('crypto')
const { encryption: { digest, iterations, salt, keyLength } } = require('../config')

const wait = (time) =>
  new Promise(resolve =>
    setTimeout(resolve, time)
  )

const encrypt = async (data) => pbkdf2Sync(data, salt, iterations, keyLength, digest).toString('hex')

const safeCompare = async (data, compare) => timingSafeEqual(Buffer.from(data), Buffer.from(compare))

module.exports = {
  wait,
  encrypt,
  safeCompare
}
