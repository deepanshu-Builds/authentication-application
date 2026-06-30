require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const cookieparser = require("cookie-parser");
const UserModel = require("./model/user");
const forgotModel = require("./model/forgotpassword");
const refreshModel = require("./model/refresj.token");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const {body , validationResult} = require("express-validator");
app.use(cookieparser());
app.set("view engine" , "ejs");
app.use(express.json());
app.use(express.urlencoded({extended : true}));    
 mongoose.connect(process.env.MONGODB_URI)
.then(()=>{
 console.log("Connected Successfully");
 }).catch((error)=>{
  console.log(error);
       })
 const limiter = rateLimit({
 windowMs : 15*60*1000,
 max : 5,
 message : "Too many attempt please try after 15 minutes !",
 skipSuccessfulRequests : true,
 keyGenerator : (req)=>{
     return req.body.email
 }
 })
  const generatorAccesstoken = (user)=>{
      return jwt.sign(
          {id: user._id , email : user.email} , 
          process.env.JWT_SECRET,
          {expiresIn : process.env.ACCESS_TOKEN_EXPIRY}
      
      );
   };
const generatorRefreshToken = (user)=>{
      return jwt.sign(
          {
              id: user._id , email : user.email
          },
          process.env.JWT_REFRESH_SECRET,
          {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY
           }
       );
    }
    
         const signUpValidation = [
 body("username")
 .notEmpty().withMessage("Username cannot be empty  ! ")
 .trim()
 .isLength({min:3}).withMessage("Username must be at least 3 charecter long !"),
 body("email")
 .notEmpty().withMessage("Email must be entered")
 .isEmail().withMessage("Email must be valid !")
 .trim()
 .normalizeEmail(),
 body("password")
 .notEmpty().withMessage("Password must be entered and must be unique")
 .isLength({min : 8}).withMessage("Password must be atleast 8 charecter long and must be unique so that hacker cannot acces it "),
 body("age")
.optional()
 .isInt({min: 18}).withMessage("Age must be positive")
            ];
 const loginValidator = [
  body("email")
  .notEmpty().withMessage("Email must be required ")
  .trim(),
  body("password")
 .notEmpty().withMessage("Password must be required !")
 .trim()
              ];

              const authMiddleware = (req , res , next)=>{
                const token = req.cookies.accessToken;
                if(!token){
                    return res.status(400).json({message : "Unauthorized "});
                }
                try{
                    const decoded = jwt.verify(token , process.env.JWT_SECRET );
                    req.user = decoded;
                    next();
                }catch(error){
                    return res.status(400).json({error : " Unauthorized ! "});
                }
              }
app.get("/" , (req , res)=>{
    res.render("signup");
})
app.post("/create" , signUpValidation , async (req , res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors : errors.array()})
    }
    let {username , email , password , age} = req.body;
    let isAlreadyExists = await UserModel.findOne({email});
    if(isAlreadyExists){
        return res.status(400).json({message : "Email already exist"});
    }
    let hash =  await argon2.hash(password);
    let UserCreated =  await UserModel.create({
        username,
        email,
        password : hash,
        age
    });
    const accessToken = generatorAccesstoken(UserCreated);
    const refreshToken = generatorRefreshToken(UserCreated);
    await refreshModel.create({
        token : refreshToken,
        user : UserCreated._id,
        expiresAt:new Date(Date.now()+7*24*60*60*1000)
    });
    res.cookie("accessToken" , accessToken ,{
        httpOnly : true,
        maxAge : 15*60*1000
    })
    res.cookie("refreshToken" , refreshToken , {
        httpOnly : true,
        maxAge : 7*24*60*60*1000
    })
    res.status(201).json({message : "User Created Successfully"});

})
app.get("/login" , (req , res)=>{
    res.render("login");

});
app.post("/login" ,  loginValidator ,async  (req , res)=>{
    const {email , password} = req.body;
    const user =  await UserModel.findOne({email});
    if(!user){
        return res.status(400).json({message : " Invalid User please enter the right eamil address"});
    }
    const isMatch = await argon2.verify(user.password , password);
    if(!isMatch){
        return res.status(400).json({message : "Invalid Credentials"});
    }
    const accessToken = generatorAccesstoken(user);
    const refreshToken = generatorRefreshToken(user);
    await refreshModel.create({
    token: refreshToken,
    user: user._id,
    expiresAt: new Date(Date.now() + 7*24*60*60*1000)
});
    res.cookie("accessToken" , accessToken , {
        httpOnly : true,
        maxAge : 15*60*1000
    });
    res.cookie("refreshToken" , refreshToken , {
        httpOnly : true,
        maxAge : 15*24*60*60*1000
    });
    res.status(201).json({message : "User logged In Succesfully !"})

})

app.post("/refresh" , async (req , res)=>{
const {refreshToken} = req.cookies;
if(!refreshToken){
   return  res.status(400).json({message : "Unauthorized : "});
}
const storedToken = await refreshModel.findOne({token : refreshToken});
if(!storedToken){
    return res.status(400).json({message : "invalid credentials"});
}
try{
    const decoded = jwt.verify(refreshToken , process.env.JWT_REFRESH_SECRET);
    const user = await UserModel.findById(decoded.id);
    if(!user){
        return res.status(400).json({message : "invalid Credentials : "});
    }
    await refreshModel.findOneAndDelete({token : refreshToken});
    const newRefreshToken = generatorRefreshToken(user);

    const newAccessToken = generatorAccesstoken(user);

    await refreshModel.create({
        token : newRefreshToken,
        user : user._id,
        expiresAt : new Date(Date.now()+7*24*60*60*1000)

    })
     res.cookie("accessToken" , newAccessToken , {
        httpOnly : true,
        maxAge : 15*60*1000   

})
    res.cookie("refreshToken" , newRefreshToken , {
        httpOnly : true,
        maxAge : 7*24*60*60*1000
    })
   


res.status(200).json({message : "Token refreshed Successfully !"})

} catch(err){
    if(err.name === "TokenExpiredError"){
        await refreshModel.findOneAndDelete({token: refreshToken});
        return res.status(401).json({message: "Session expired, please login again"});
    }
    return res.status(401).json({message: "Invalid token"});

}

});
app.get("/profile" , authMiddleware , (req , res)=>{
    res.render("profile");
})
app.get("/logout" ,async (req , res)=>{
    const {refreshToken} = req.cookies;
    await refreshModel.findOneAndDelete({token : refreshToken});
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.render("logout")

})

app.get("/logout-all" , authMiddleware , async (req , res)=>{
    try{
    await refreshModel.deleteMany({user : req.user._id});
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
      return res.status(200).json({message: "Logged out from all devices!"});
    }catch(error){
        console.log(error);
    }
});

const generateOTP = () => {
   return  Math.floor(Math.random()*900000)+100000;
}


app.post("/forgot" , async (req , res)=>{
let {email} = req.body;
try{
    const user = await UserModel.findOne({email});
    if(!user){
        return res.status(401).json({
            message : "Invalid Email or wrong Password"
        });
    }
const otp = generateOTP();
await forgotModel.create({
    otp,
    user : user._id,
    expiresAt : new Date(Date.now()+5*60*1000)
});
let transpoter = nodemailer.createTransport({
    host : "smtp.ethereal.email",
    port : 587,
    auth : {
        user : "coby.hilll@ethereal.email",
        pass : "cKqWxpYjRhkB4S4KvS"
    }
});
const mailOptions = {
    from : "coby.hilll@ethereal.emai",
    to : user.email,
    subject : `Yout otp is ${otp}`,
    text : "Please do not share this otp to anyone "
}

transpoter.sendMail(mailOptions , function (error , info){
    if(error){
        console.error("There is error and that is " , + error);
        return res.status(400).json({message : "Something went wrong"});
    }
    else{
        console.log(info.messageId);
    }
    return res.status(200).json({message : "OTP sent to  your eamil and it is valid for 5 minutes :"})
})

}catch(err)
{
    console.log(err);
return res.status(401).json({message : "Something went wrong "})
}
});
app.post("/verify-otp" ,async  (req , res)=>{
let {otp , newPassword} = req.body;


try {
    const findOTP = await forgotModel.findOne({otp});
if(!findOTP){
    return res.status(400).json({message : "OTP is not valid" })
    
}
    if (Date.now() > findOTP.expiresAt) {
        await forgotModel.deleteOne({_id : findOTP._id});
    return res.status(400).json({ message: "OTP has expired" });
}  
const hash =  await argon2.hash(newPassword);
await UserModel.findByIdAndUpdate(findOTP.user , {
    password : hash

}) ;
await forgotModel.findOneAndDelete({_id: findOTP._id});
return res.status(200).json({message : "password updated successfully !"});
}catch(error){
    console.log(error);
  res.status(401).json({message : "Something went wrong !"});
      
}


});






app.listen(3000 , ()=>{
    console.log("Server is running at the port Number 3000");
})