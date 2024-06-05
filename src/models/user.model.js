const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'username is required'],
        unique: true,
        maxLength: 50,
    },
    email: {
        type: String,
        required: [true, 'email is required'],
        unique: true,
        maxLength: 250,
    },

    password: {
        type: String,
        required: [true, 'password is required'],
    }
});

var user = new mongoose.model('users', userSchema);
module.exports = user;