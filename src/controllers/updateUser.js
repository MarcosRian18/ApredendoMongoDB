const User = require('../models/users')

module.exports = {
    putUsers: async (req,res)=> {
    try {
      const userId = req.params.id
      const updateUser = await User.findByIdAndUpdate(userId, req.body, {
        new: true
      })
      console.log(updateUser)
      if (!updateUser) {
        return res.status(404).json({ message: 'Usuário não encontrado' })
      }
      return res.status(200).json("Dados do Usuário alterados: " + updateUser)
    } catch (error) {
      console.log("o erro é esse: ", error.message)
      return res.status(500).json({ message: 'Erro no servidor!' })
    }
  }
}

