



require("dotenv").config()
const express = require("express");
const app = express();
const UserModel = require("./model/user")
const bcrypt = require("bcrypt");
const path = require("path");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken")
app.set("view engine", "ejs");

const cookieParser = require("cookie-parser");
mongoose.connect(process.env.MONGODB_URI);
app.use(express.json());
app.use(express.urlencoded({extended : true}))
app.use(cookieParser());
app.use(express.static(path.join(__dirname , "public")));
app.get("/" , (req , res )=>{
    res.render("signup")
})
app.post("/create" , (req , res)=>{
let {username , email , password , age} = req.body;
bcrypt.genSalt(10 , (err , salt)=>{
    bcrypt.hash(password , salt , async (err , hash)=>{
 let UserCreated =   await UserModel.create({
        username,
        email,
        password:hash,
        age
      })
      let token = jwt.sign({email} , process.env.JWT_SECRET)
      res.cookie("token" , token);
      res.send(UserCreated);
    })
})
})
app.get("/login" , (req , res)=>{
    res.render("login");
})
app.get("/logout" , (req , res)=>{
    res.clearCookie("token");
    res.render("logout")
})
app.listen(process.env.PORT || 4000 , ()=>{
    console.log("Started Successfully");
})
