const express = require('express');
const router = express.Router();
const {AddBlogPage,AddBlog,UpdateBlogPage,UpdateBlog,DeleteBlog,DeleteBlogPage,DeleteAllBlogPage,DeleteAllBlogs} = require('../controller/Blog');

router.get('/addblog',AddBlogPage);
router.post('/addblog',AddBlog);
router.get('/updateblog/:id',UpdateBlogPage);
router.post('/updateblog/:id',UpdateBlog);
router.post('/deleteblog/:id',DeleteBlog);
router.get('/deleteblog/:id',DeleteBlogPage);
router.get('/deleteallblogs',DeleteAllBlogPage);
router.post('/deleteallblogs',DeleteAllBlogs);

module.exports = router;