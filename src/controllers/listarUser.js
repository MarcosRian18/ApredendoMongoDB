
const User = require("../models/users")


// Controller function to create a new user
module.exports = {
   
    getAllUsers: async (req, res) => {
      try {
        const users = await User.find()
        return res.json(users)
      } catch (err) {
        console.log("o erro é esse: ", err.message)
        return res.status(500).json({ message: 'Erro no servidor!' })
      }
    },
  }
    