const mongoose = require('mongoose');

const User = mongoose.model('User', new mongoose.Schema(
    {
        name:{
            type: String,
            require: true
        },
        username: {
            type: String,
            require: true
        },
        password: {
            type: String,
            require: true
        },
        token: {
            type: String,
            default: ''
        }   
    },{
        timestaps: true,
    })
)

module.exports = User;
