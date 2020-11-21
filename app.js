import dotenv from 'dotenv';
import express from 'express';
import ejs from 'ejs';
import passport from 'passport';
import passportLocal from 'passport-local';
import session from 'express-session';
import bcrypt from 'bcrypt';
import flash from 'express-flash';
import methodOverride from 'method-override';


dotenv.config();
const app = express();
const localStrategy = passportLocal.Strategy;

const PORT = process.env.PORT || 8080;

// Template Engine
app.set('view engine', 'ejs');

// Body Parser
app.use(express.urlencoded({extended: false}));

//Body parser allows form data to be viewed in the request body but in newer versions of express we have express.urlencoded which solves
//this problem eliminating the need for the body-parse module

// Flash Messages
app.use(flash());

// DB
let users = []

// Session
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}))

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Method Override
app.use(methodOverride('_method'));

// Passport Strategy
passport.use( new localStrategy({ 
                                        // This tells passport the names of properties in the req POST body to look at 
        usernameField: 'email',         // Look for req.body.email
        passwordField: 'password'       // Look for req.body.password
    },
    async (email, password, done) => {        // The first two parameters passed are usernameField and passwordField



        const target = users.find(user => user.email === email);
        
        if(target == null) {

            console.log("wrong email")
            return done(null, false, { message: 'No user with that email' });

        }

        try {
            //sends target object to next passport function
            if(await bcrypt.compare(password, target.password)){

                console.log("success");
                return done(null, target, {message: 'success' });

            }
            else {

                console.log("incorrect password");
                return done(null, false, { message: 'password incorrect' });
            }

        } catch (e) {

            return  done(e.message);
        
        }
    }
));

passport.serializeUser( (user, done) => {
     // Creates session based on user id req.session.passport.user = {id: user.id }
     // and sends user id to next passport function
    done(null, user.id);
});

const findByID = (id) => users.find( user => user.id === id);
passport.deserializeUser( (id, done) => {
    const target = findByID(id);     //checks if user id for passport session matches db id and you can ONLY PASS A VALUE
    return done(null, target);      //the next function will attach the target object to req.user
    
});

const isLogin = (req, res, next) => {
    if(req.user) return next();

    res.redirect('/login');
}

const isNotLogin = (req, res, next) => {
    if(req.user) res.redirect('/dashboard');

    else next();
}


// Routes
app.get('/home', (req, res) => {
    req.flash('info', 'welcome to my website');
    res.render('home');
});

app.get('/login', isNotLogin, (req, res) => {
    console.log(req.flash());
    res.render('login');
});

app.post('/login', passport.authenticate('local', { 
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));



app.get('/register', isNotLogin, (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { name, password, email } = req.body;
    const hashPword = await bcrypt.hash(password, 10);


    users.push({
        id: Date.now().toString(),
        name,
        password:hashPword,
        email
    });

    console.log(users);

    res.redirect('/login');
});

app.get('/dashboard',isLogin, (req, res) => {
    res.render('dashboard', {user : req.user.name});
});

app.delete('/dashboard', (req, res) => {
    req.logOut();
    res.redirect('/home')
})



app.listen(PORT, () => {
    console.log(`Listening on port: ${PORT}`);
});
