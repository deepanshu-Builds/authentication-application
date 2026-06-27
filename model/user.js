const mongoose = require("mongoose");

const UserSchema = mongoose.Schema({
    username : {
        type:String,
        required:true,
        trim : true
        
    },
    email : {
        type: String,
        unique : true,
        required:true,
        lowercase:true
    },
    password : {
    type:String,
    required:true,
    trim : true
    },
    age : {
        type: Number,
        required:true,
        min: 15,
    }
    
});
module.exports = mongoose.model("User" , UserSchema )




