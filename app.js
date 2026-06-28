require("dotenv").config()
const express = require("express");
const app = express();
const { body, validationResult } = require('express-validator');
const UserModel = require("./model/user")
const bcrypt = require("bcrypt");
const path = require("path");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
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


        // MIDDLEWARE FOR AUTHENTICATION
        const authMiddleware = (req , res , next)=>{
            const token = req.cookies.token;
            
            if(!token) return res.status(401).json({message : "Unauthorized"});
            try{
                const decoded = jwt.verify(token , process.env.JWT_SECRET);
                req.user = decoded;
                next();
            }catch(err){
                return res.status(401).json({message : "Unauthorized"});
            }

            
        }
             //   EXPRESS RATE LIMITER



             const loginLimiter = rateLimit({
                windowMs: 15*60*1000,
                max: 5,
                message : "To many login attempt from this IP , Please try again after 15 minutes",
                skipSuccessfulRequests : true,
               keyGenerator : (req)=>{
                return req.body.email;
               }}
            )


             



app.post("/create" , [

    //USERNAME VALIDATION


   body("username")
            .notEmpty().withMessage("Username is required")
            .trim()
            .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long")
            .matches(/^[a-zA-Z0-9_]+$/).withMessage("Username must contain only letters and numbers"),
           
           
            // EMAIL VALIDATION
            body("email")
            .notEmpty().withMessage("Email is required")
            .isEmail().withMessage("Please provide a valid email")
            .trim()
            
            .normalizeEmail(),
           
           
            // PASSWORD VALIDATION
            body("password")
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
           
           
            // AGE VALIDATION
            body("age")
            .optional()
            .isInt({ min: 0 }).withMessage("Age must be a positive integer")
] 


, async (req , res)=>{

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
let {username , email , password , age} = req.body;

let isAlreadyExist = await UserModel.findOne({email});
if(isAlreadyExist) return res.status(400).json({message : "Email already exists"});



   const hash = await bcrypt.hash(password , 10 )
 let UserCreated =   await UserModel.create({
        username,
        email,
        password:hash,
        age
      })
      let token = jwt.sign({email} , process.env.JWT_SECRET , {expiresIn : "7d"})
      res.cookie("token" , token);
      res.send(UserCreated);
    })


app.get("/login" , (req , res)=>{
    res.render("login");
});
app.post("/login"  , async (req , res)=>{
let user = await UserModel.findOne({email: req.body.email});
if(!user) return res.render("error");
bcrypt.compare(req.body.password , user.password , (err , result)=>{
    if(result){
        let token = jwt.sign({email : user.email} , process.env.JWT_SECRET)
      res.cookie("token" , token);
      res.render("profile");

    }
    else res.send("Something went wrong ! ");
})
})
app.get("/profile" , authMiddleware , (req , res)=>{
    res.render("profile");
})
app.get("/logout" , (req , res)=>{
    res.clearCookie("token");
    res.render("logout")
})
app.listen(process.env.PORT || 4000 , ()=>{
    console.log("Started Successfully");
})
