const catchAsync = require('../utils/catchAsync');
const Review = require('../models/reviewModel');
const User = require('../models/userModel');
const Booking = require('../models/bookingModel');
const factory = require('./handlerfactory');
const AppError = require('../utils/appError');


exports.setTourUserIds = (req, res, next) => {
  // Allow Nested Routes
  if (!req.body.tour) req.body.tour = req.params.tourId;
  if (!req.body.user) req.body.user = req.user.id;
  next();
};

exports.restrictUsers = catchAsync(async (req, res, next) => {
  //1. Get User
  const user = await Booking.findOne({user: req.user.id});

  
  if (!user)
    return next(
      new AppError('You cannot perform this action, please book a tour first', 403)
    );

  next();
});

exports.getAllReviews = factory.getAll(Review)
exports.getReview = factory.getOne(Review);
exports.createReview = factory.createOne(Review);
exports.updateReview = factory.UpdateOne(Review);
exports.deleteReview = factory.deleteOne(Review);
