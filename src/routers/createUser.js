const express = require('express')
const router = express('router')
const criarUsuario = require('../controllers/createUser')

// Create a new user
router.post("/teste", criarUsuario.createUser)



module.exports = router
