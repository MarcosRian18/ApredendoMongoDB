const mongoose = require('../config/dbConfig')

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: (email) => /\S+@\S+\.\S+/.test(email),
      message: 'Por favor insira o email corretamente.',
    },
  },
  password: {
    type: String,
    required: true,
    minlength: [8, "A senha deve conter no minimo 8 caractéres."]
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});
userSchema.index
const User = mongoose.model('User', userSchema)

module.exports = User