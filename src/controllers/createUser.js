const User = require('../models/users')

// Controller function to create a new user
module.exports = {
  createUser : async (req, res) => {
    try {
      const { name, password, email } = req.body
     
      if (!name || !password || !email) {
        return res.status(400).json({ message: 'Todos os campos devem ser fornecidos.' })
      }
  
      if (password.length < 8) {
        return res.status(400).json({ message: 'A senha deve ter pelo menos 8 caracteres.' })
      }
      
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'O email fornecido é inválido.' })
      }
  
      const resultado = await User.create(req.body)
      console.log(req.body)
      return res.status(201).json(resultado)
    } catch (err) {
      console.log('o erro é esse: ', err.message)
      return res.status(500).json({ message: 'Erro no servidor!' })
    }
  }
 
}