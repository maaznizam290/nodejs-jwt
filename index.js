const express = require('express');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const PORT = process.env.PORT || 3001;
const app = express();
app.use(express.json());

const users = [];
const verifyToken = (req,res,next)=>{
    if(!req.headers.authorization){
        return res.status(400).send("Unauthorized Request");
    }
    const token = req.headers["authorization"].split("")[1];
if(!token){
    return res.status(400).send("No Token is being provided");
}
try{
    const decoded = jwt.verify(token,process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
}catch(err){
        res.status(400).send("Invalid TOken");
}
};
// Users API
app.get("/api/users",async(req,res)=>{
res.json(users);
});

// Signup API 
app.post("/api/register",async(req,res)=>{
    const user = req.body;
    if(!user.email || !user.password){
        return res.status(400).send("Username and Password are required");
    }
    const hash = await bcrypt.hashSync(user.password,10);
    user.password = hash;
    users.push(user);
    res.json(user);
});
app.post("/api/login",async(req,res)=>{
    const user = req.body;
    
    const oldUser = users.find((user)=>user.email === req.body.email);
    if(!oldUser){
        return res.status(400).send("Credential Error");
    }

    const PasswordValid = await bcrypt.compare(
        user.password,
        oldUser.password
    );
    if(!PasswordValid){
        return res.status(400).send("Credential Error");
    }
    const token = jwt.sign({user},process.env.JWT_SECRET,{
        expiresIn:"2h",
    });
    res.json({token});
})

app.listen(PORT,()=>{
    console.log(`Server is running at ${PORT}`)
})