const User = require('../models/users')

module.exports = {
    deleteUser: async (req, res) => {
        try {
          const userId = req.params.id
          const deletedUser = await User.findByIdAndDelete(userId)
          if (!deletedUser) {
            return res.status(404).json({ message: 'Usuário não encontrado' })
          }
          console.log("O registro " + deletedUser + " foi deletado com sucesso!")
          return res.status(200).json("O Usuário " + deletedUser+ " foi deletado com sucesso!")
        } catch (err) {
          console.log("o erro é esse: ", err.message)
          return res.status(500).json({ message: 'Erro no servidor!' })
        }
      },
}