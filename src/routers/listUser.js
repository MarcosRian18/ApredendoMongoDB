const express = require('express')
const router = express('router')
const listarUsuario = require('../controllers/listarUser')

// Create a new user
router.get('/usuarios', listarUsuario.getAllUsers)
module.exports = router
