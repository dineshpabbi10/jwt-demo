const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

app.use(cors())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Secret keys config
const config = {
    AUTH_TOKEN_SECRET : process.env.AUTH_TOKEN_SECRET || 'demo',
    REFRESH_TOKEN_SECRET : process.env.REFRESH_TOKEN_SECRET || 'demo',
}

// define users
const users = [
    {
        username : "user1",
        password : "password1",
        roles : ["admin","dev"]
    },
    
    {
        username : "user2",
        password : "password2",
        roles : ["dev"]
    },
    
    {
        username : "user3",
        password : "password3",
        roles : ["user"]
    },
    
    {
        username : "user4",
        password : "password4",
        roles : ["admin"]
    },
]

// define storage for generated tokens
const tokens = {};

const authMiddleware = (req,res,next)=>{
    let auth_token = req.headers['x-access-token'];

    // no auth token provided in headers
    if(auth_token === null){
        res.status(401).json({message:"Not authenticated"});
    }

    // verify token signature and decode information
    jwt.verify(auth_token,config.AUTH_TOKEN_SECRET,(err,decoded)=>{
        // token signed with wrong signature or tampered token
        if(err){
            res.status(401).json({message:"Not authenticated"});
        }else{
            // token verified succesfully , add user info to req
            req.username = decoded.username;
            req.roles = decoded.roles;
            next();
        }
    })
}

app.post("/login",(req,res,next)=>{
    //get username and password
    let username = req.body.username;
    let password = req.body.password;

    // find user from list
    let user = users.filter((elem)=>{
        if(elem.username === username){
            return elem;
        }
    });

    // user not found
    if(user.length === 0){
        res.status(401).json({message:"User not found"});
    }
    // user found but password incorrect
    else if (user.password !== password){
        res.status(401).json({message:"Password incorrect"});
    }
    // user found and password incorrect
    else{
        // generate auth_token which expires in 20 seconds
        let auth_token  = jwt.sign({
            username : user.username,
            roles : user.roles
        },config.AUTH_TOKEN_SECRET,{expiresIn:'20'});

        // generate refresh_token which never expires
        let refresh_token = jwt.sign({
            username : user.username,
            roles : user.roles,
        },config.REFRESH_TOKEN_SECRET)

        // add token generated for particular username to hashmap
        tokens[username] = {
            refresh_token,
            auth_token
        }

        // send tokens as response
        res.status(201).json({
            message:"Logged in successfully",
            refresh_token : refresh_token,
            auth_token : auth_token
        })
    }
});


// an endpoint that just needs authentication
app.get("/helloworld",authMiddleware,(req,res,next)=>{
    res.status(200).json({
        message:"Hello user : "+req.username
    });
});


// an endpoint that requires admin role
app.get("/helloadmin",authMiddleware,(req,res,next)=>{
    if(req.roles.includes("admin")){
        res.status(200).json({
            message:"Hello admin : "+req.username
        });
    }else{
        res.status(403).json({
            message:"You do not have the role to access this resource"
        });
    }
});

app.post("/refreshtoken",(req,res,next)=>{
    let refresh_token = req.body.refresh_token;
    // no refresh token provided
    if(refresh_token === null){
        res.status(401).json({message:"No refresh token provided"});
    }
    //verify refresh token
    else{
        jwt.verify(refresh_token,config.REFRESH_TOKEN_SECRET,(err,decoded)=>{
            // if a tamprered token is provided
            if(err){
                res.status(401).json({message:"Invalid refresh token provided"});
            }
            // token provided is valid and decoded
            else{
                let auth_token = jwt.sign({
                    username : decoded.username,
                    roles : decoded.roles
                },config.AUTH_TOKEN_SECRET,{expiresIn:'20'});

                res.status(201).json({
                    refresh_token,
                    auth_token
                })
            }
        })
    }
});


// start server on port 3003
app.listen(3008,()=>{
    console.log("Server started at port 3008");
})

