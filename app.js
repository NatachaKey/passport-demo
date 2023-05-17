// if I search for this documentation from browser- I can´t find this section in Documentation
//http://www.passportjs.org/concepts/authentication/password/ (given in the lesson)
// is it because of the old version of the website? I  think this link refers to the same instructions https://www.passportjs.org/howtos/password/

require('dotenv').config();
var bcrypt = require('bcryptjs');
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const MongoDBStore = require('connect-mongodb-session')(session);

//created new collection in mongo db
var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions',
});

// Catch errors
store.on('error', function (error) {
  console.log(error);
});

const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

//SET UNIQUE USERNAME -LATER
const User = mongoose.model(
  'User',
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();

//set the directory where views/templates are located. __dirname is a special variable in Node.js that represents the current directory path of the script file. 
// we are telling Express to look for views/templates in the current directory.
app.set('views', __dirname);
//set the view engine to be used for rendering the views. In this case, it's set to 'ejs', which stands for Embedded JavaScript OR js code in our HTML templates that generate dynamic content.
app.set('view engine', 'ejs');
//in other words with these two lines we're telling Express to look for views in the current directory and use EJS as the templating engine for rendering those views

//setting up the LocalStrategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: 'Incorrect username' });
      }
      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password' });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);

//serialize (converting a complex data structure (such as a user object) into a format that can be easily stored and retrieved)
//here only the user.id property should be used for serialization. This means that when the user is authenticated, 
//only their id value will be stored in the session, rather than the entire user object.
//=when the user is authenticated, only their id value will be stored in the session, rather than the entire user object.
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

//When subsequent requests are made by the same user, the serialized user identifier is used to retrieve the full user object from the session through deserialization.
//f the user is successfully found, the user object is passed as the second argument to the done function, indicating successful deserialization. we pass 'null' as an argument- when there is no error
passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: store,
  })
);

// sets up Passport to work with Express and prepares it for authentication handling.
app.use(passport.initialize());
//enables Passport to restore authentication state from the session, allowing authenticated users to stay logged in across multiple requests.
app.use(passport.session());
//parse URL-encoded data from incoming requests to handle form submissions that send data in the application/x-www-form-urlencoded format.
//extended: false option indicates that the URL-encoded data should be parsed using the built-in querystring library of Node.js
app.use(express.urlencoded({ extended: false }));
//in other words express.urlencoded() middleware enables our application to handle URL-encoded form data.

// sets up a variable currentUser in the res.locals object, making it available in our views for convenient access to the currently authenticated user information.
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

const authMiddleware = (req, res, next) => {
  if (!req.user) {
    if (!req.session.messages) {
      req.session.messages = [];
    }
    req.session.messages.push("You can't access that page before logon.");
    res.redirect('/');
  } else {
    next();
  }
};

//show error messages to the user . The messages are put in an array, req.session.messages.
app.get('/', (req, res) => {
  let messages = [];
  if (req.session.messages) {
    messages = req.session.messages;
    req.session.messages = [];
  }
  res.render('index', { messages });
});

app.get('/sign-up', (req, res) => res.render('sign-up-form'));

//delete all the session information at logoff time
app.get('/log-out', (req, res) => {
  req.session.destroy(function (err) {
    res.redirect('/');
  });
});

// HIDE PASSWORD
app.post('/sign-up', async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({
      username: req.body.username,
      password: hashedPassword,
    });
    res.redirect('/');
  } catch (err) {
    return next(err);
  }
});

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
    failureMessage: true,
  })
);

//the session can be used to store state, in this case the number of page visits.
app.get('/restricted', authMiddleware, (req, res) => {
  if (!req.session.pageCount) {
    req.session.pageCount = 1;
  } else {
    req.session.pageCount++;
  }
  res.render('restricted', { pageCount: req.session.pageCount });
});

app.listen(3000, () => console.log('app listening on port 3000'));
