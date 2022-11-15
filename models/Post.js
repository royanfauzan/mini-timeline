const mongoose = require('mongoose');

const Post = mongoose.model('Post', new mongoose.Schema(
    {
        owner:{
            type : mongoose.Types.ObjectId,
            ref: 'User',
            require:true
        },
        text: {
            type: String,
            require: true
        },
        likes: [{ type : mongoose.Types.ObjectId, ref: 'User' }] 
    },{
        timestaps: true,
    })
)

module.exports = Post;
