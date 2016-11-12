"use strict";

// Dependencies               ==================================================
let express     = require('express');
let app         = express();
let bodyParser  = require('body-parser'); // will let us get parameters from our POST requests
let mongoose    = require('mongoose');
let morgan      = require('morgan'); // will log requests to the console so we can see what is happening
let jwt         = require('jsonwebtoken'); // used to create, sign, and verify tokens

let Config      = require('./Config'); // get our config file
let User        = require('./User'); // get our mongoose model

// Initialization             ==================================================
mongoose.connect(Config.database); // connect to database
app.use(bodyParser.json()); // get our request parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(morgan('dev')); // use morgan to log requests to the console
app.use(express.static(__dirname + "/../client")); // default route

// Routes                     ==================================================
/*app.get('/setup', function(req, res) {
  // create a sample user
  var nick = new User({
    name: 'Nick Cerminara',
    password: 'password',
  });
  // save the sample user
  nick.save(function(err) {
    if (err) throw err;
    console.log('User saved successfully');
    res.json({ success: true });
  });
});*/

// API routes                 ==================================================
let apiRoutes = express.Router(); // get an instance of the router for api routes

apiRoutes.post('/signup', function(req, res) {
  User.findOne({ name: req.body.name }, function(err, existingUser) {
    if (existingUser) {
      return res.status(409).send({ success: false, message: 'Name is already taken' });
    }
    if (!req.body.name || !req.body.password) {
      return res.status(400).send({ success: false, message: 'Bad creditenials' });
    }
    var user = new User({
      //displayName: req.body.displayName,
      name: req.body.email,
      password: req.body.password
    });
    user.save(function(err, result) {
      if (err) { res.status(500).send({ success: false, message: err.message }); }
      var token = jwt.sign(user, Config.secret, { expiresIn: 1440 }); // expires in 24 hours
      res.json({ success: true, message: 'User & token created', token: token });
      //res.send({ token: token });
    });
  });
});

apiRoutes.post('/login', function(req, res) {
  User.findOne({ name: req.body.name }, '+password', function(err, user) { // ?+password
    if (err) throw err;
    if (!user) {
      //res.json({ success: false, message: 'Authentication failed. Wrong creditenials.' });
      return res.status(401).send({ success: false, message: 'Authentication failed. Wrong creditenials' }); // User not found
    }
    user.comparePassword(req.body.password, function(err, isMatch) {
      if (!isMatch) {
        //res.json({ success: false, message: 'Authentication failed. Wrong creditenials.' });
        return res.status(401).send({ success: false, message: 'Authentication failed. Wrong creditenials' }); // Wrong password
      }
      // if user is found and password is right then create a token
      var token = jwt.sign(user, Config.secret, { expiresIn: 1440 }); // expires in 24 hours
      res.json({ success: true, message: 'Token created', token: token });
      //res.send({ token: token });
    });
  });
});

// route middleware to verify a token
apiRoutes.use(function(req, res, next) {
  var token = req.body.token || req.query.token || req.headers['x-access-token']; // check header or url parameters or post parameters for token
  if (token) {
    jwt.verify(token, Config.secret, function(err, decoded) { // verifies secret and checks exp
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token' });
      } else {
        req.decoded = decoded; // if everything is good, save to request for use in other routes
        next();
      }
    });
  } else {
    return res.status(401).send({ success: false, message: 'No token provided' }); // if there is no token return an error
  }
});

// route to show a message
apiRoutes.get('/', function(req, res) {
  res.json({ message: 'Welcome to authentication API' });
});
// route to return all users
apiRoutes.get('/users', function(req, res) {
  User.find({}, function(err, users) { res.json(users); });
});
// apply the api routes
app.use('/auth', apiRoutes);

// Start the server           ==================================================
app.listen(Config.port);
console.log('App is listening on port ' + Config.port);
