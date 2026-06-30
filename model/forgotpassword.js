const mongoose = require ("mongoose");
const forgotPassword = new mongoose.Schema({
    otp : {
        type : String,
        unique : true,
        required: true
    },
    user : {
        type : mongoose.Schema.Types.ObjectId,
        ref : "User",
        required : true,

    },
    expiresAt : {
        type : Date,
        required : true,
    }

}
);
module.exports = mongoose.model("ForgetPassword" , forgotPassword);