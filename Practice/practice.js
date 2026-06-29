                        // HOW TO MAKE THE MIDDLEWARE WORK


                    const express = require("express");
                    const app = express();
                    app.set("view engine" , "ejs");
                    app.use(express.json());
                    app.use(express.urlencoded({extended : true}));


                    // MIDDLEWARE
                    const authMiddleware = (req , res , next)=>{
                        const token = req.cokkies.token;
                        if(!token){
                            return res.redirect("signup");
                        }
                        try{
                            const decoded = jwt.verify(token , JWT_URL_SECRET);
                            User.req = decoded;
                        }catch(error){
                            return res.status(400).json({message : "Unauthorized User"})

                        }
                    }

                             // EXPRESS RATE LIMITING 


                        const loginLimiter = rateLimit({
                            windowMs : 15*60*1000,
                            max : 5,
                            skipSuccessfulRequests : true,
                            message : "To many attempt try again after 15 minutes",
                            keyGenerator:(req)=>{
                                return req.body.email;
                            }
                        })

                    app.get("/profile" , authMiddlewar , (req , res )=>{
                        return res.render("profile");
                    })




                    app.listen(3000 , () => {
                        console.log("srever is running at the port 3000");
                    })