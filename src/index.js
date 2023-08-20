const express = require('express')
const cors = require("cors")
const app = express()
const cve = require('./routers/createCve')
const createUser = require('./routers/createUser')
const listUSer = require('./routers/listUser')
const updateUser = require('./routers/updateUser')
const deletedUser = require('./routers/deleteUser')

app.use(express.json())
// User route
app.use(cors())
app.use(cve)
app.use(createUser)
app.use(listUSer)
app.use(updateUser)
app.use(deletedUser)

// Start the server
app.listen(3000, () => {
  console.log(`Servidor rodando...`)
});
