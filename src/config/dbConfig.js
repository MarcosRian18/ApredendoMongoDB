const mongoose = require('mongoose')

mongoose.connect('mongodb://root:example@172.24.0.3:27017/').then(() => {
    console.log("Banco conectado com sucesso!")
}).catch((err) => {
    console.log("O erro é esse: " , err)
})
mongoose.Promise = global.Promise

module.exports = mongoose