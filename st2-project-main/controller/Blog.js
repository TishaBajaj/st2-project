const Blog = require('../model/Blog');
const User = require('../model/User');

module.exports.DisplayAllBlogs = async (req,res) => {
    let blogs  = await Blog.find({is_verify:true});
    if (req.session.isLoggedIn) {
        res.render('landingpage.hbs',{blogs:blogs,user: req.session.user});
    }
    else{
        res.render('landingpage.hbs',{blogs:blogs});
    }
}

module.exports.AddBlogPage = (req,res) => {
    res.render('addblog.hbs',{user: req.session.user});
}

module.exports.AddBlog = async (req,res) => {
    const {imgUrl,title, caption,category} = req.body;
    const newblog = new Blog({imgUrl:imgUrl,title:title,caption:caption,category:category,user_id:req.session.user._id});
    await newblog.save();
    let user = await User.findById(req.session.user._id);
    console.log(newblog._id);
    user.Blogs.push(newblog._id);
    console.log(user);
    await user.save();
    res.redirect("/")
}

module.exports.UpdateBlogPage = async (req,res) => {
    let blog = await Blog.findById(req.params.id);
    res.render('adminpages/updateblog.hbs',{blog,user: req.session.user});
}

module.exports.UpdateBlog = async (req, res) => {
    const {imgUrl, title, caption,category} = req.body;
    await Blog.findByIdAndUpdate(req.params.id,{imgUrl:imgUrl,title:title,caption:caption,category:category});
    res.redirect("/admin");
}

module.exports.DeleteBlog = async (req,res) => {
    await Blog.findByIdAndDelete(req.params.id);
    res.redirect("/admin");
}

module.exports.DeleteBlogPage = async (req,res) => {
    const blog = await Blog.findById(req.params.id);
    res.render('adminpages/deleteblog.hbs',{blog:blog,user: req.session.user})
}

module.exports.DeleteAllBlogs = async (req,res) => {
    await Blog.deleteMany({});
    res.redirect("/admin");
}

module.exports.DeleteAllBlogPage = (req,res) => {
    res.render('adminpages/deleteallblogs.hbs',{user: req.session.user});
}