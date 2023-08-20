const mongoose = require('mongoose')

const Schema = mongoose.Schema

const CVESchema = new Schema({
    containers: Object,
    cveMetadata: Object,
    dataType: String,
    dataVersion: String
})

const CVEModel = mongoose.model('CVE', CVESchema)

module.exports = CVEModel
