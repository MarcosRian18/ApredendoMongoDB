const express = require('express')
const router = express('router')
const cveController = require('../controllers/createCve')


router.post('/import-cves', cveController.importCVEs)
// router.get('/list-cves', cveController.listCVE)
router.get('/findCve/:id', cveController.FindCve)

module.exports = router
