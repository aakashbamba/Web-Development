require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our Little Secret",
    resave: false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose); // Used for hash and salting passwords and Storing into our MongoDB database.
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); //Encryption Method is not that secure so we dont use it.

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());    //We remove these two lines
// passport.deserializeUser(User.deserializeUser());


//Use the Below Strategy to serialise and deserialise 
//Below  Works for all different strategies and not just for local strategy
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"    //Add this manually to avoid Google+ Account
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res)
{
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res)
{
    res.render("login");
});

app.get("/register", function(req, res)
{
    res.render("register");
});

app.get("/secrets", function(req,res){
    // if(req.isAuthenticated())
    // {
    //     res.render("secrets");
    // }
    // else{
    //     res.redirect("/login");
    // }
    
    //Since we dont want to show this page for priviledge to only single user (User sirf apna secret khud hi dekh paye ko avoid krne ke liye.), i.e, all users can view each others' secrets, so I have commented it since i dont need that part.
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        } else{
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    });

});

app.get("/submit", function(req,res){
    if(req.isAuthenticated())
    {
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;
    
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");  
                });
            }
        }
    });
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

app.post("/register", function(req,res){

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash){

    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash 
    //     });
    //     newUser.save(function(err){
    //         if(err)
    //         {
    //             console.log(err);
    //         }
    //         else {
    //             res.render("secrets");
    //         }
    // });
    
    // });
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else{
            passport.authenticate("local") (req, res, function(){      //Setup a cookie
                res.redirect("/secrets");   //if the User was already logged in then he will be directly accessing this page. So we have to setup that route.
            });
        }
    });

});
app.post("/login", function(req, res){
    // const username = req.body.username;
    // const password = req.body.password;
    // User.findOne({email: username}, function(err, foundUser){
    //     if(err)
    //     {
    //         console.log(err);
    //     }
    //     else{
    //         if(foundUser)
    //         {
    //             bcrypt.compare(password, foundUser.password, function(err, result){
    //                 if(result === true)
    //                 {
    //                     res.render("secrets");

    //                 }
    //             });
                
    //         }
    //     }
    // });
    const user = new User({
         email : req.body.username,
         password : req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local") (req, res, function(){      //Setup a cookie
                res.redirect("/secrets");   //if the User was already logged in then he will be directly accessing this page. So we have to setup that route.
            });
        }
    });
   
});

app.listen(3000, function(){
    console.log("Server started on Port 3000");
});

//OAuth : Open Standard Authentication - basic 
