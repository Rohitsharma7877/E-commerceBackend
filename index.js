require('dotenv').config();
const express= require("express");
const app = express();
const mongoose= require("mongoose");
const cors= require("cors")
const session= require('express-session')
const passport = require('passport')
// const SQLiteStore = require('connect-sqlite3')(session)
const LocalStrategy= require('passport-local').Strategy;
const crypto = require('crypto')
const jwt = require("jsonwebtoken")
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt= require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser')
const { createProduct } = require("./controller/Product");
const productsRouters = require('./routes/Products')
const categoriesRouter = require('./routes/Categories')
const brandRouter= require("./routes/Brand")
const usersRouter= require('./routes/Users')
const authRouter= require('./routes/Auth')
const cartRouter = require('./routes/Cart')
const orderRouter = require('./routes/Order');
const { isAuth, sanitizeUser, cookieExtractor } = require("./services/Common");
const path = require('path');
const { Order } = require('./model/Order');
const { env } = require('process');


const endpointSecret = process.env.ENDPOINT_SECRET;

app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (request, response) => {
    const sig = request.headers['stripe-signature'];

    let event;

    try {
      event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
    } catch (err) {
      response.status(400).send(`Webhook Error: ${err.message}`);
      return;
    }

    // Handle the event
    switch (event.type) {
      case 'payment_intent.succeeded':
        const paymentIntentSucceeded = event.data.object;

        const order = await Order.findById(
          paymentIntentSucceeded.metadata.orderId
        );
        order.paymentStatus = 'received';
        await order.save();

        break;
      // ... handle other event types
      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    response.send();
  }
);

// JWT options



const opts= {}
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey= process.env.JWT_SECRET_KEY;


//const app=express()
app.use(express.static(path.resolve(__dirname, 'build')));
app.use(cookieParser())
app.use(session({
  secret:'keyboard cat',
  resave: false, 
  saveUninitialized: false,
  // store: new SQLiteStore({db:'sessions.db', dir:'./var/db'})
}))


app.use(passport.authenticate('session'))

app.use(cors({
  exposedHeaders:['X-Total-Count']
}))
app.use(express.json());

app.use('/products', isAuth(), productsRouters.router)
app.use('/categories', isAuth(),categoriesRouter.router)
app.use('/brands', isAuth(),brandRouter.router)
app.use('/users',isAuth(), usersRouter.router)
app.use('/auth',authRouter.router)
app.use('/cart',isAuth(), cartRouter.router)
app.use('/order',orderRouter.router)

app.get('*', (req, res) =>
  res.sendFile(path.resolve('build', 'index.html'))
);



// Passport Strategies
passport.use(
  'local',
  new LocalStrategy({ usernameField: 'email' }, async function (
    email,
    password,
    done
  ) {
    // by default passport uses username
    console.log({ email, password });
    try {
      const user = await User.findOne({ email: email });
      console.log(email, password, user);
      if (!user) {
        return done(null, false, { message: 'invalid credentials' }); // for safety
      }
      crypto.pbkdf2(
        password,
        user.salt,
        310000,
        32,
        'sha256',
        async function (err, hashedPassword) {
          if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
            return done(null, false, { message: 'invalid credentials' });
          }
          const token = jwt.sign(
            sanitizeUser(user),
            process.env.JWT_SECRET_KEY
          );
          done(null, { id: user.id, role: user.role, token }); // this lines sends to serializer
        }
      );
    } catch (err) {
      done(err);
    }
  })
);

passport.use(
  'jwt',
  new JwtStrategy(opts, async function (jwt_payload, done) {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, sanitizeUser(user)); // this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

// this creates session variable req.user on being called from callbacks
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, role: user.role });
  });
});
// this changes session variable req.user when called from authorized request
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// Payments


// const stripe = require("stripe")('sk_test_tR3PYbcVNZZ796tH88S4VQ2u');



// const calculateOrderAmount = (items) => {
  
//   return 1400;
// };
const stripe = require('stripe')(process.env.STRIPE_SERVER_KEY);

app.post('/create-payment-intent', async (req, res) => {
  const { totalAmount, orderId } = req.body;

  // Create a PaymentIntent with the order amount and currency
  const paymentIntent = await stripe.paymentIntents.create({
    amount: totalAmount * 100, // for decimal compensation
    currency: 'inr',
    automatic_payment_methods: {
      enabled: true,
    },
    metadata: {
      orderId,
    },
  });

  res.send({
    clientSecret: paymentIntent.client_secret,
  });
});





main().catch(err=> console.log(err));


// async function main(){
//   await mongoose.connect('mongodb://127.0.0.1:27017/bigBasket');
//   console.log('MongoDB connected')

// } 


async function main(){
  await mongoose.connect(process.env.URL)
  console.log('MongoDB connected')
}
app.listen(9000,()=>{
    console.log("Server is Running")
})
