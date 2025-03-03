import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from 'jsonwebtoken';
import express from 'express';
import bcrypt from 'bcrypt';
import path from 'path';

const app = express();

app.use(express.static(path.join(path.resolve(),'public')));
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));


mongoose.connect("mongodb+srv://rnafork:aman110304@cluster0.t30fq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", {
    dbName:"Authenticator"
}).then(console.log("Mongoose is connected..."));

const anyschema = mongoose.Schema({
    gmail:String,
    name:String,
    pass:String
});

const anymodel = await mongoose.model("registers2", anyschema);

app.get('/', async(req, res)=>{
    const token = req.cookies.token;
    if(token){
        const decode = jwt.verify(token, 'aman');
        req.aman = await anymodel.findById(decode.id);
        res.render('logout.ejs');
    } else {
        res.redirect('/login');
    }
});

app.get('/register', (req, res)=>{
    res.render('register.ejs')
});

app.get('/login', (req, res)=>{
    res.render('login.ejs');
})

app.post('/register', async(req, res)=>{
    const hashp = await bcrypt.hash(req.body.password, 10);
    const obj = {
        name:req.body.name,
        gmail:req.body.email,
        pass:hashp
    }

    let user = await anymodel.findOne({gmail:obj.gmail});
    if(user) return res.redirect('/login');
    user = await anymodel.create(obj);
    console.log(user);

    const token = jwt.sign({id:user._id}, 'aman');
    res.cookie('token', token, {
        httpOnly:true,
        expires:new Date(Date.now() + 5*60*1000)
    });

    res.redirect('/');
});

app.post('/login', async(req, res)=>{
    const gmail = req.body.email;
    const pass = req.body.password;

    const user = await anymodel.findOne({gmail});
    if(!user) return res.redirect('/register');

    const isMatch = await bcrypt.compare(pass, user.pass);
    if(!isMatch) return res.redirect('/login', {msg:'invailed password'});

    const token = jwt.sign({id:user._id}, 'aman');
    res.cookie('token', token, {
        httpOnly:true,
        expires:new Date(Date.now() + 5*60*1000)
    });

    res.redirect('/');
});

app.get('/logout', (req, res)=>{
    res.cookie('token', null, {
        httpOnly:true,
        expires:new Date(Date.now())
    });
    res.redirect('/');
})

app.listen(3000, ()=>{
    console.log("Express is connected on port 3000");
})