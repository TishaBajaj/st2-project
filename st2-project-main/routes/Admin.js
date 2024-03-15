const express = require('express');
const User = require('../model/User');
const Token = require('../model/Token');
const router = express.Router();
const {ObjectId} = require('mongoose');
const {Login,LoginPage,RegisterPage,Register,AdminPage,Logout,CategoryPage,Category,ProfilePage,Admin} = require('../controller/Admin');
var fs = require("fs");

router.post('/login',Login);
router.get('/login',LoginPage);
router.post('/logout',Logout);
router.get('/register',RegisterPage);
router.post('/register',Register);
router.get('/admin',AdminPage);
router.post('/admin/:id',Admin);
router.get('/category',CategoryPage);
router.post('/category',Category);
router.get('/profile',ProfilePage);
router.get("/user/verify/:id/:token",async(req,res)=>{
    const {id,token} = req.params;
    const link = `/user/verify/${id}/${token}`;
    fs.readFile("./static/css/login.css", "utf-8", (err,data)=>{
        fs.readFile("./static/css/navbar.css", "utf-8", (err,navbar)=>{
            return res.render("verify.hbs",{link: link, style: data, navbar: navbar})
        })
    })
})
router.post("/user/verify/:id/:token",async(req,res)=>{
    const {otp} = req.body;
    const {id}=req.params;
    console.log(otp);
    let user= await User.findOne({_id:id});
    let token = await Token.findOne({token:req.params.token});
    if(!token || !user){
        res.send("Something went wrong");
    }
    if(token.otp == otp){
        await User.updateOne({_id:user.id,verify:true});
        user.is_verify=true;
        await user.save();
        await Token.findByIdAndDelete(token._id);
        res.send("Email verified successfully");
    }
})

module.exports = router;