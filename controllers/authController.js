const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {promisify} = require('util');
const jsonwebtokens = require('jsonwebtoken');
const AppError = require('../utils/appError');
const catchAsync = require('./../utils/catchAsync');
const User = require('../models/userModel');
const SendMail = require('../utils/sendMail');
const tokenApp = id => {
    return jsonwebtokens.sign({id: id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES_IN});
};
exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create(req.body);
    const token = tokenApp(newUser._id);
    res.status(201).json({
        message: "success",
        token: token,
        data: newUser
    })
});
exports.login = catchAsync(async (req, res, next) => {
    const {email, password} = req.body;
    if(!email || !password) {
        return next(new AppError('email password not provided', 400))
    }
        const user = await User.findOne({email}).select("+password");
        console.log(user);
        // const correct = await user.correctPassword(password, user.password);
        if (!user || !await user.correctPassword(password, user.password)) {
            return next(new AppError("email of password incorrect", 401));
        }
    const token = tokenApp(user._id);
    res.status(200).json({
        status: 'success',
        token
    });
});
exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if  (req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1];
    };
    if (!token) {
        return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    const veryToken = promisify(jsonwebtokens.verify)
    const decoded = await veryToken(token, process.env.JWT_SECRET);

    const curentUser = await User.findById(decoded.id);
    console.log(curentUser)
    if(!curentUser) {
        return next(
            new AppError(
                'The user belonging to this token does no longer exist.',
                401
            )
        );
    }
    if (curentUser.changedPasswordAfter(decoded.iat)) {
        return next(
            new AppError('User recently changed password! Please log in again.', 401)
        );
    }


    req.user = curentUser;
    next();
});
exports.restrictTo = (...roles) => {
    return (req, res, next) => {

        if(!roles.includes(req.user.role)) {
            return next(new AppError('kho du quyen', 403))
        }
        next();
    }
};
exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({email: req.body.email});
    console.log(user);
    if (!user) {
        return next(new AppError("Khong tim thay dia chi email", 404));
    }

    const resetPassword = user.createPasswordResetToken();
    await user.save({validateBeforeSave: false});
    const resetURL = `${req.protocol}://${req.get(
        'host'
    )}/api/v1/users/resetPassword/${resetPassword}`;
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
    try {
        SendMail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 min)',
            message,
            html: `<h2>${user.email}</h2>
            <div>${message}</div>
`
        });

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email!'
        });
    }catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return next(
            new AppError('There was an error sending the email. Try again later!'),
            500
        );
    }
});
exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
        passwordResetToken: hashToken,
        passwordResetExpires:  { $gt: Date.now() }
    });
    if (!user) {
        return next(new  AppError('Token sai'), 400)
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken  = undefined;
    user.passwordResetExpires  = undefined;
    if(user.password  !== user.passwordConfirm ){
        return next (new AppError("password error", 400))
    }
    user.save();
    console.log(user);
    res.status(200).json({
        status: 'success',
        token: tokenApp(user.id),
       user
    });
});
