const express = require('express')

// middlewares
const error = require('./middlewares/error')
const logger = require('./middlewares/logger')
const defaultHandler = require('./middlewares/default')
const docs = require('./middlewares/docs')

// routes
const todos = require('./todos/routes')
const users = require('./users/routes')

const app = express()
const router = express.Router()

router.use(express.json())
router.use(logger())
router.use('/todos', todos)
router.use('/users', users)
router.use(defaultHandler)
router.use(error())

app.use('/api', router)
app.use('/docs', docs)

app
  .listen(3000, '0.0.0.0', () => {
    console.log('Server started successfully')
  })
  .once('error', (error) => {
    console.error('Server failed', error)
    process.exit(1)
  })
