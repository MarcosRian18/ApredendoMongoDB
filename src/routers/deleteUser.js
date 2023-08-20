const express = require('express')
const router = express('router')
const usuarioDelete = require('../controllers/deleteUser')

// Create a new user
router.delete('/deleteUSer/:id', usuarioDelete.deleteUser)
module.exports = router