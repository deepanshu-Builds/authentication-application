const mongoose = require("mongoose");
mongoose.connect(process.env.MONGODB_URI)
.then(()=>{
    console.log("Connected");
})
.catch((error)=>{
    console.error(error);
})
const UserSchema = mongoose.Schema({
    username : {
        type:String,
        required:true
        
    },
    email : {
        type: String,
        required:true
    },
    password : {
type:String,
required:true
    },
    age : {
        type: String,
        required:true
    }
    
});
module.exports = mongoose.model("User" , UserSchema )




