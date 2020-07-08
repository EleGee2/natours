const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const compression = require('compression');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./Routes/tourRoutes.js');
const userRouter = require('./Routes/userRoutes.js');
const reviewRouter = require('./Routes/reviewRoutes.js');
const bookingRouter = require('./Routes/bookingRoutes.js');
const viewRouter = require('./Routes/viewRoutes.js');
const { models } = require('mongoose');
const User = require('./models/userModel');
const authController = require('./controllers/authController');


//const verifyRouter = require('./Routes/verifyRoutes.js');

const app = express();


app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

app.get('/verify/:token', async (req, res) => {
  const token = req.params.token;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const currentUser = await User.findByIdAndUpdate(decoded.id, {
    confirmed: true,
  });
  if (!currentUser) {
    return next(new AppError('Token is invalid or expired', 400));
  }
  return res.redirect('http://127.0.0.1:3000/login');
});

app.post('/token', authController.verifyRefreshToken);

// 1. GLOBAL MEDDLEWARE

//Set Security HTTP Headers
app.use(helmet());

// Development Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit Requests From Same IP
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many request from this IP, please try again later',
});
app.use('/api', limiter);

// Body Parser, Reading Data From Body Into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data Sanitization against NOsql query injection
app.use(mongoSanitize());

// Data sanitize against XSS
app.use(xss());

// Prevent Parameter Pollutiom
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsAverage',
      'ratingsQuantity',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  })
);

app.use(compression());

// Serving Static Files
app.use(express.static(path.join(__dirname, 'public')));

// Test Middleware
app.use((req, res, next) => {
  //console.log('Hello from the middleware');
  next();
});

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  //console.log(req.cookies);
  next();
});

// ROUTES
app.use('/', viewRouter);
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);
app.use('/api/v1/bookings', bookingRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
