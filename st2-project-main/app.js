const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const routerblog = require('./routes/Blog');
const routeradmin = require('./routes/Admin');
const hbs = require('hbs');
const dotenv = require('dotenv').config();
hbs.registerHelper('ifEquals', function(arg1, arg2, options) {
    return (arg1 == arg2) ? options.fn(this) : options.inverse(this);
});
const session = require('express-session');
const {DisplayAllBlogs} = require('./controller/Blog');
app.use(session({
    secret: 'secret',
    // resave: true,
    // saveUninitialized: true,
    // cookie: {secure: true}
}))
hbs.registerPartials(__dirname+'/views/partials');
app.use(express.static(path.join(__dirname, 'static')));
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.set('view engine','hbs');
app.get('/',DisplayAllBlogs);
function checkloggedin(req,res,next){
    if(req.session.isLoggedIn){
        next();
    }
    else{
        res.send('login first to proceed')
    }
}
app.use("/",routeradmin);
app.use("/",checkloggedin,routerblog);

mongoose.connect("mongodb://127.0.0.1:27017/blogsapp").then(()=>{
    app.listen(3000,(req,res)=>{
        console.log("Server is running at port 3000");
    })
})