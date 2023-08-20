const express = require('express')
const router = express('router')
const updateUser = require('../controllers/updateUser')

// Create a new user
router.put('/alterarUser/:id', updateUser.putUsers)
module.exports = router
