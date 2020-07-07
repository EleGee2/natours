const { promisify } = require('util');
const crypto = require('crypto');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const AppError = require('../utils/appError');
const Email = require('../utils/email');
if (typeof localStorage === 'undefined' || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  global.localStorage = new LocalStorage('./scratch');
}

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const RefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET_1, {
    expiresIn: process.env.JWT_SECRET_EXPIRES_IN,
  });
};

const sendJWT = function (user, status_code, res) {
  const token = signToken(user._id);
  const refresh = RefreshToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;
  user.refreshTokens = undefined;
  res.status(status_code).json({
    status: 'success',
    token,
    refresh,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    role: req.body.role,
  });
  const token = signToken(newUser._id);
  const url = `${req.protocol}://${req.get('host')}/verify/${token}`;

  sendJWT(newUser, 201, res);
  await new Email(newUser, url).sendConfirmEmail();
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }
  const user = await User.findOne({ email }).select('+password');

  if (user.confirmed === false) {
    return next(new AppError('Please confirm your email to Login', 400));
  }

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }
  const refreshToken = RefreshToken(user._id);
  if (user)
    await User.findOneAndUpdate({ email }, { refreshTokens: refreshToken });
  localStorage.setItem('refresh', refreshToken);
  sendJWT(user, 201, res);
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};

exports.verifyRefreshToken = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      const user = jwt.decode(token);
      const currentUser = await User.findById(user.id);
      if (!currentUser) {
        return next(new AppError('This Token does no longer exist', 401));
      }

      const refreshToken = currentUser.refreshTokens[0];
      if (refreshToken == null)
        return res
          .status(401)
          .json({ status: 'Failed, Please provide a refresh token' });
      if (currentUser.refreshTokens.includes(refreshToken))
        //return next(new AppError('There was a problem', 403));
        jwt.verify(refreshToken, process.env.JWT_SECRET_1, (err, user) => {
          if (err) return res.sendStatus(403);
          const accessToken = signToken(user._id);
          const refreshToken = RefreshToken(user._id);
          res.json({
            status: 'Token Issued',
            accessToken: accessToken,
            refreshToken: refreshToken,
          });
        });
    }
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1. CHECK IF TOKEN EXISTS
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(
      new AppError(
        'You are not logged in! Please log in to get information',
        401
      )
    );
  }

  // 2. VALIDATE token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  // 3.Check if user exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('This Token does no longer exist', 401));
  }

  // 4. Check if any change occured in the token
  if (currentUser.passwordChangedAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please log in again', 401)
    );
  }

  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

// Only for rendered pages
exports.isLoggedIn = async (req, res, next) => {
  // 1. Verify Token
  if (req.cookies.jwt) {
    try {
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );

      // 2.Check if user exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next();
      }

      // 3. Check if any change occured in the token
      if (currentUser.passwordChangedAfter(decoded.iat)) {
        return next();
      }

      // 4. There is a logged in User
      req.user = currentUser;
      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next();
    }
  }

  next();
};

exports.isSignedIn = async (req, res, next) => {
  const url = `${req.protocol}://${req.get('host')}/me`;
  if (req.cookies.jwt) {
    const decoded = await promisify(jwt.verify)(
      req.cookies.jwt,
      process.env.JWT_SECRET
    );
    const user = await User.findById(decoded.id);
    await new Email(user, url).sendConfirmEmail();
  }
  next();
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perfom this action', 403)
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1. GET USER BASED ON POSTED EMAIL
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address', 404));
  }

  //2. GENERATE THE RANDOM RESET Token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  //3. SEND IT TO USER'S EMAIL
  try {
    const resetUrl = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    await new Email(user, resetUrl).sendPasswordReset();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordTokenExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was a problem sending email', 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1. Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordTokenExpires: { $gt: Date.now() },
  });

  // 2. If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordTokenExpires = undefined;
  await user.save();

  // 3. Update changedPasswordAt property for the user

  // 4. Log the user in, send JWT
  sendJWT(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  //1. Get User From Collection
  const user = await User.findById(req.user.id).select('+password');

  //2. Check If POSTed Current Password Is Correct
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  //3. If So, Update Password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  //4. Log User in, Send JWT
  sendJWT(user, 200, res);
});
