const mongoose = require('mongoose');;

const userSchema = mongoose.Schema({
    Username: {type: String,unique: true, required: true},
    Password: {type:String, required: true},
    is_verify: {type: Boolean, default: false},
    Admin: {type: Boolean, default: false},
    Blogs: [{ type: mongoose.Types.ObjectId}]
});

module.exports = mongoose.model("User",userSchema);