const Tour = require('../models/toursModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const User = require('../models/userModel');
const Booking = require('../models/bookingModel');
const Review = require('../models/reviewModel');

exports.getOverview = catchAsync(async (req, res, next) => {
  // 1. GET TOUR DATA
  const tours = await Tour.find();

  //2. BUILD TEMPLATE

  // 3. RENDER THAT TEMPLATE USING TOUR DATA FROM 1

  res.status(200).render('overview', {
    title: 'All tours',
    tours,
  });
});

exports.getTour = catchAsync(async (req, res, next) => {
  // 1. GET ALL THE DATA FOR THE REQUESTED TOUR (INCLUDING REVIEWS AND GUIDES)
  const tour = await Tour.findOne({ slug: req.params.slug }).populate({
    path: 'reviews',
    fields: 'review rating user',
  });
  if (!tour) {
    return next(new AppError('There is no tour with that name', 404));
  }
  try {
    const bookings = await Booking.find({ user: req.user.id });
    const tourIDs = bookings.find((el) => el.tour.name === tour.name);
    if (!tourIDs) tours = undefined;
    else {
      tours = tourIDs.tour.name;
    }

    res.status(200).render('tour', {
      title: tour.name,
      tour,
      tours,
    });
  } catch (error) {
    res.status(200).render('tour', {
      title: tour.name,
      tour,
    });
  }
});

exports.getLoginForm = catchAsync(async (req, res) => {
  res.status(200).render('login', {
    title: 'Log into your account',
  });
});

exports.getSignupForm = catchAsync(async (req, res) => {
  res.status(200).render('signup', {
    title: 'Sign up',
  });
});

exports.getAccount = (req, res) => {
  res.status(200).render('account', {
    title: 'Your account',
  });
};

exports.getForgotPasswordForm = catchAsync(async (req, res) => {
  res.status(200).render('forgotpassword', {
    title: 'Reset Password',
  });
});

exports.createReview = catchAsync(async (req, res) => {
  const user = await Booking.findOne({
    user: req.user.id,
    tour: req.params.tourid,
  });
  const tourID = req.params.tourid;

  if (!user)
    res.status(400).render('error', {
      title: 'Not Allowed',
      msg: 'You cannot perform this action, Book this Tour.',
    });
  else {
    res.status(200).render('review', {
      title: 'Create Review',
      tourID,
    });
  }
});

exports.getMyTours = catchAsync(async (req, res, next) => {
  // 1. Find all bookings
  const bookings = await Booking.find({ user: req.user.id });

  // 2. Find tours with the returned IDs
  const tourIDs = bookings.map((el) => el.tour);
  const tours = await Tour.find({ _id: { $in: tourIDs } });

  res.status(200).render('overview', {
    title: 'Booked Tours',
    tours,
  });
});

exports.getMyReviews = catchAsync(async (req, res) => {
  // 1. Find all reviews
  const reviews = await Review.find({ user: req.user.id });

  res.status(200).render('reviews', {
    title: 'Reviewed Tours',
    reviews,
  });
});

exports.updateUserData = catchAsync(async (req, res, next) => {
  const updateUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      name: req.body.name,
      email: req.body.email,
    },
    {
      new: true,
      runValidators: true,
    }
  );

  res.status(200).render('account', {
    title: 'Your account',
    user: updateUser,
  });
});
