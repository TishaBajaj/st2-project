const mongoose = require('mongoose');

const blogSchema = mongoose.Schema({
    imgUrl: String,
    title: {type:String, required: true},
    caption: String,
    category: {type:String, required: true},
    is_verify: {type: Boolean, default: false},
    user_id: {type: mongoose.Types.ObjectId}
});

module.exports = mongoose.model("Blog",blogSchema);