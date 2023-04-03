//jshint esversion:6
require('dotenv').config(); //copy from dotenv documentation
const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')

// ----------------------------------------------npm authentication packages---------------------------------------------------------------------//

//const encrypt = require('mongoose-encryption')   //removing it because we will use hashing

//const md5 = require('md5') //hashing

//we will now use bcypt not hashing
// const bcrypt = require('bcrypt')
// const saltRounds = 10;

//we will now use passport and express-session
//no need to require passport-local mongoose
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

//-------------------------------------------------Google OAuth20---------------------------------------------------------//
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// -------------------------------------------------------------------------------------------------------------------//

const app = express()

app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended:true}))

// -------------------------------------------------------------------------------------------------------------  -----//
              //-------initializing session (always put this code between all app.js and mongoose.connect1---------//
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}))

              //--------initailizing passport----------------------------------------------------------------------//
app.use(passport.initialize())
app.use(passport.session()) //telling passport to set-up session
//--------------------------------------------------------------------------------------------------------------------//

//connecting mongodb databse
mongoose.connect('mongodb://127.0.0.1:27017/userDB');

// -----------------------------------------------------Schema--------------------------------------------------------------//

//creating schema
// const userSchema = {
//     email:String,
//     password:String
// }

//creating new schema as defined in the encryption package documentation
// const userSchema = new mongoose.Schema({
//     email:String,
//      password:String
// })

//-----------------------------------setting up passport-local mongoose-----------------------------------------------//
const userSchema = new mongoose.Schema({
  email:String,
   password:String,
   googleId:String, //add this when using Google OAuth20
   secrets:[String] //Both secrets: [{ type: String }] and secrets: [String] are correct ways to define an array of strings in a Mongoose schema in JavaScript.
  })

userSchema.plugin(passportLocalMongoose)

const User = new mongoose.model("User", userSchema) 

//----------------------------------------passport-local mongoose documentation------------------------------------------------//

passport.use(User.createStrategy());
//passport.serializeUser(User.serializeUser());             //we will replace both of these with the code available on the below link to use Google OAuth20
//passport.deserializeUser(User.deserializeUser())

//--------------------------------(https://www.passportjs.org/concepts/authentication/sessions/)------------------------------//

//we commented out the previous two serialise and deserialise code to use the new codes from the above link for Google Oauth20
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

//---------------------------------------------------Google OAuth20--------------------------------------------------//
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileUrl :"https://www.googleapis.com/oauth2/v3/userinfo" //this will make to retrieve info not from google+ account but from "userinfo" endpoint  
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile)
  User.findOne({ googleId: profile.id })
  .then(user => {
      if (user) {
          return cb(null, user);
      }
      else {
          const newUser = new User({ googleId: profile.id });
          newUser.save()
              .then(user => {
                  return cb(null, user);
              })
              .catch(err => {
                  return cb(err);
              });
      }
  })
  .catch(err => {
      return cb(err);
  });
})
);
// -------------------------------------------------------------------------------------------------------------------//

//copy both these LINES from the documentation
//defining 'secret' by second method to encrypt our database
//line1:
//const secret = "Thisisourlittlesecret.";
//adding mongoose encrypt as a plugin to our schema and we are gonna pass over secret as a JS object 
//LINE2:
//userSchema.plugin(encrypt, {secret:secret, encryptedFields:['password']})
//its important to add thi plugin to the schema before creating Mongoose model

//after creating .env file and defining secret inside it we have to change the above code
// userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields:['password']}) //removing it because we will use hashing 


// -------------------------------------------------------------------------------------------------------------------//

//creating model
// const User = new mongoose.model("User", userSchema) 
// "User" is name of collection and const User is name of Model
//userSchema is written after coma to specify the schema whose model has been created

// -------------------------------------------------------------------------------------------------------------------//

app.get('/',(req,res)=>{
    res.render('home');
})

//-------------------------------------Google OAuth20-----------------------------------------------------------------//
  app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

//----------------------------------------------------------------------------------------------------------------------//
app.get('/login',(req,res)=>{
    res.render('login');
})

app.get('/register',(req,res)=>{
    res.render('register');
})

app.get('/secrets', async(req,res)=>{
  // if(req.isAuthenticated()){  //we want that anybody whether registered or not can see the secrets
  //   res.render("secrets")     //that is why we are removing these lines of code
  // }else{
  //   res.redirect("/login")
  // }

  const foundUsers = await User.find( { "secrets": { $ne:null } } ) //finding all the users which have secrets
  try{
      res.render("secrets", {userWithSecrets:foundUsers} ) //The render() method expects a second argument that is an object containing the data that you want to pass to the template.
  }catch(err){
   console.log(err)
  }
})

app.get('/logout',(req,res)=>{   //passport comes with .login(), .()logout, ()register methods which we can access by req
  req.logOut((err)=>{
   if(err){ console.log(err)}
  })           
  res.redirect('/')
})

app.get('/submit', (req,res)=>{
  if(req.isAuthenticated()){ //if req.isAuthenticated is true it means user is logged in
    res.render("submit")
  }else{
    res.redirect("/login") //if user is not logged in then user is redirected to login page
  }
})

app.post('/submit', async (req, res) => {
  const submittedSecret = req.body.secret;
  const foundUser = await User.findById(req.user.id).exec();
  if (foundUser) {
    //foundUser.secret=submittedSecret 
    //we need to use 'push' because 'secrets' is an array otherwise above line of code just replace index[0] element of the array everytime the code will run
    foundUser.secrets.push(submittedSecret); 
    //console.log(submittedSecret)
    //console.log(foundUser.secrets)
    //console.log(foundUser);
    try {
      const savedUser = await foundUser.save();
      //console.log(savedUser);
      res.redirect('/secrets');
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect('/register');
  }
});

// -----------------------------------------------using encryption and hashing--------------------------------------------------------------------//

//creating register route to catch the POST request
// app.post('/register',async(req,res)=>{
// //now we will create our new user here
// // const {email,password} = req.body
// try{
//     // await new User({email:req.body.username, password:req.body.password}).save() //we have to modify it because we have to use hashing
//     await new User(
//         {email:req.body.username,
//          password:md5(req.body.password)//modifying the above code to use hashing
//         }).save()

//         console.log("Registered Successfully")
//         res.render("secrets"); //only registered user would get access of the secrets page
//     }catch(err){
//     res.status(500).json({message:"something is wrong"})
// }
// })

//------------------------------------------------using bcrypt-----------------------------------------------------------------------------------//

//creating register route to catch the POST request
// app.post('/register',(req,res)=>{
//   //now we will create our new user here
//   try{
//       bcrypt.hash(req.body.password, saltRounds,async (err, hash)=>{
//         // Store hash in your password DB.
//         await new User(
//           {email:req.body.username,
//            password:hash   //hash generated will be saved in the password in database
//           }).save()
  
//           console.log("Registered Successfully")
//           res.render("secrets"); //only registered user would get access of the secrets page
//       })}catch(err){
//       res.status(500).json({message:"something is wrong"})
//   }
//     })


//------------------------------------------------using passport-----------------------------------------------------//
//this package comes with .login(), .()logout, ()register methods which we can access by req
app.post('/register',(req,res)=>{

  const {username,password} = req.body    //username and passwords are the user's identification by which user wants to get registered in the data
  User.register({username},password, (err, user)=>{
    if(err){
      console.log(err)
      res.redirect('/register')
    }else{
        passport.authenticate("local")(req,res,()=>{  //'local means local authentication strategy
          res.redirect('/secrets')
        })
    }
  })
})


// -------------------------------------------------------------------------------------------------------------------//

// app.post("/login", async(req,res)=>{
//     const {username,password}=req.body
//     try{
//         await User.findOne({
//             email:username,
//             //password:password 
//             password:md5(password) //modifying the above code to use hashing //here we are saying that the login password must be same as the register password
//         });
//         res.render("secrets");
//     }catch(err){
//         res.status(500).json({message:"something is wrong"})
//     }
// app.post("/login", function(req, res){
//         const username = req.body.username;
//         const password = md5(req.body.password);

//         const foundUser = User.findOne({email: username});
//         console.log(foundUser)
//         if (foundUser.password === password) {
//             res.render("secrets");
//         } else {
//         console.log("err");
//     }
// })


// ----------------------------------------------better than above code---------------------------------------------------------------------//

                                //----------------using md5------------------------//
// app.post("/login", async function(req, res) {
//     const username = req.body.username;
//     const password = md5(req.body.password);
  
//     try {
//       const foundUser = await User.findOne({ email: username });
//       console.log(foundUser);
//       if (!foundUser) {
//         console.log("User not found.");
//         res.redirect("/login");
//       } else {
//         if (password === foundUser.password) {
//           res.render("secrets");
//         } else {
//           console.log("Incorrect password.");
//           res.redirect("/login");
//         }
//       }
//     } catch (err) {
//       console.log(err);
//       res.redirect("/login");
//     }
//   });
                              //---------------using bcrypt-------------------------//
                              
// app.post("/login", async function(req, res) {
//     const username = req.body.username;
//     const password = req.body.password;
  
//     try {
//       const foundUser = await User.findOne({ email: username });
//       console.log(foundUser);
//       if (!foundUser) {
//         console.log("User not found.");
//         res.redirect("/login");
//       } else {
//         bcrypt.compare(password, foundUser.password, function(err, result) {
//           if(result === true){
//             res.render("secrets");
//           } else {
//             console.log("Incorrect password.");
//             res.redirect("/login");
//           }
//       }); 
//       }
//     } catch (err) {
//       console.log(err);
//       res.redirect("/login");
//     }
//   });

//------------------------------------------------using passport-----------------------------------------------------//

app.post('/login', passport.authenticate('local', {   //local means local authentication strategy
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));
// -------------------------------------------------------------------------------------------------------------------//

app.listen(3000, function(){
    console.log("server is running")
})
