import bcrypt from "bcryptjs";
import crypto from "crypto";

import User from "../models/user.model.js";
import Profile from "../models/profile.model.js";
import Transaction from "../models/transaction.model.js";
import ServiceRequest from "../models/serviceRequest.model.js";
import { generateVerificationCode } from "../utils/generateVerificationCode.js";
import { verifyCaptcha } from "../utils/verifyCaptcha.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { evaluateContext } from "../utils/contextEvaluator.js";
import { getLocationName } from "../utils/getLocationName.js";
import {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendResetPasswordEmail,
  sendResetSuccessEmail,
  sendAccountDeletionEmail,
  sendNewDeviceLoginAlert,
  sendSuspiciousActivityWarning,
  sendTwoFactorAuthEmail,
} from "../nodemailer/emails.js";
import { updateContextProfile } from "../utils/updateContextProfile.js";
import { generateAccountDetails } from "../utils/generateAccountDetails.js";

export const signup = async (req, res) => {
  const { email, password, name, context, captcha } = req.body;
  try {
    if (!email || !password || !name) {
      throw new Error("All fields are required!");
    }

    if (!captcha) {
      return res
        .status(400)
        .json({ success: false, message: "Captcha is required!" });
    }

    const userAlreadyExists = await User.findOne({ email });

    if (userAlreadyExists) {
      return res
        .status(400)
        .json({ success: false, message: "User Already Exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationCode();
    
    // Generate unique account details
    const accountDetails = generateAccountDetails();

    const isHuman = await verifyCaptcha(captcha);
    console.log("Captcha verification result:", isHuman);
    if (!isHuman) return res.status(403).json({ error: "Bot detected" });

    const user = new User({
      accountNumber: accountDetails.accountNumber,
      ifscCode: accountDetails.ifscCode,
      email,
      password: hashedPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 60 * 1000, // 1 minute
      trustedIPs: [context.ip], // Initialize with the current IP
      trustedDevices: [context.device], // Initialize with the current device
      locations: [
        {
          lat: context.location.latitude,
          lon: context.location.longitude,
        },
      ], // Initialize with the current location
      contextLogs: [
        {
          ip: context.ip,
          device: context.device,
          location: {
            lat: context.location.latitude,
            lon: context.location.longitude,
            locationName:
              (await getLocationName(
                context.location.latitude,
                context.location.longitude
              )) || "Unknown", // Use provided location name or default to "Unknown"
          },
          timestamp: new Date(),
          riskScore: 0, // Initial risk score for this context
        },
      ],
      behavioralProfile: {
        typingSpeed: context.typingSpeed,
        loginHours: context.loginHours,
      }, // Initialize with the current behavioral profile
      riskScore: 0, // Initialize risk score
    });

    await user.save();

    // jwt
    generateTokenAndSetCookie(res, user._id);

    await sendVerificationEmail(user.email, verificationToken);

    res.status(201).json({
      success: true,
      message: "User Created Successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password, context, captcha } = req.body;
  try {
    if (!email || !password) {
      throw new Error("All fields are required!");
    }

    if (!captcha) {
      return res
        .status(400)
        .json({ success: false, message: "Captcha is required!" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found!" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(400)
        .json({ success: false, message: "Wrong Password!" });
    }

    // Inside login route:
    const isHuman = await verifyCaptcha(captcha);
    console.log("Captcha verification result:", isHuman);
    if (!isHuman) return res.status(403).json({ error: "Bot detected" });

    try {
      const isDeviceTrusted = user.trustedDevices?.includes(context.device);
      if (!isDeviceTrusted) {
        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpiresAt = resetTokenExpiresAt;
        await user.save();
        await sendNewDeviceLoginAlert(
          user.email,
          user.name,
          context,
          `${process.env.CLIENT_URL}/reset-password/${resetToken}`
        );
      }

      const risk = evaluateContext(context, user);

      // Risk-based authentication logic
      if (risk >= 10) {
        // Block login and send warning email for high risk
        await sendSuspiciousActivityWarning(
          user.email,
          user.name,
          context,
          risk
        );
        return res.status(403).json({
          success: false,
          message:
            "Suspicious activity detected, login blocked for your security. Check your email for details.",
        });
      } else if (risk >= 5) {
        // Require 2FA for medium risk
        const verificationToken = generateVerificationCode();
        user.verificationToken = verificationToken;
        user.verificationTokenExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
        await user.save();

        await sendTwoFactorAuthEmail(
          user.email,
          user.name,
          verificationToken,
          context
        );

        await updateContextProfile(user, context, risk);

        return res.status(200).json({
          success: true,
          message: "Two-factor authentication required",
          require2FA: true,
          email: user.email,
        });
      }

      user.lastLogin = new Date();
      await updateContextProfile(user, context, risk);
      await user.save();
    } catch (error) {
      console.error("Error evaluating context:", error);
      return res.status(500).json({ success: false, message: "Server error" });
    }

    generateTokenAndSetCookie(res, user._id);

    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      user: {
        ...user._doc,
        password: undefined,
        trustedIPs: undefined,
        trustedDevices: undefined,
        locations: undefined,
        behavioralProfile: undefined,
        riskScore: undefined,
      },
    });
  } catch (error) {
    console.log("Error during login:", error);
    res.status(400).json({ success: false, message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { verificationCode } = req.body;
  try {
    const user = await User.findOne({
      verificationToken: verificationCode,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();

    await sendWelcomeEmail(user.email, user.name);

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log("Error verifying email:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const resendVerificationCode = async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required!",
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found!" });
    }
    if (user.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "User already verified!" });
    }
    const verificationToken = generateVerificationCode();
    user.verificationToken = verificationToken;
    user.verificationTokenExpiresAt = Date.now() + 60 * 1000; // 1 minute
    await user.save();
    await sendVerificationEmail(user.email, verificationToken);
    res.status(200).json({
      success: true,
      message: "Verification code resent successfully",
    });
  } catch (error) {
    console.log("Error resending verification code:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      res.status(400).json({
        success: false,
        message: "Email is required!",
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found!" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiresAt;
    await user.save();
    // Here you would send the reset token to the user's email
    sendResetPasswordEmail(
      user.email,
      `${process.env.CLIENT_URL}/reset-password/${resetToken}`
    );

    res.status(200).json({
      success: true,
      message: "Password reset token sent to your email",
    });
  } catch (error) {
    console.log("Error during forgot password:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    if (!newPassword) {
      return res
        .status(400)
        .json({ success: false, message: "New password is required!" });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiresAt: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpiresAt = undefined;
    await user.save();

    sendResetSuccessEmail(user.email);

    res.status(200).json({
      success: true,
      message: "Password reset successfully",
    });
  } catch (error) {
    console.log("Error during reset password:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const logout = async (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ success: true, message: "Logged out successfully" });
};

export const checkAuth = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error("Error checking authentication:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const deleteAccount = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Delete profile if exists
    await Profile.deleteOne({ user: req.userId });
    // Delete all transactions where user is sender or recipient
    await Transaction.deleteMany({ $or: [ { userId: req.userId }, { recipientId: req.userId } ] });
    // Delete all service requests by this user's email
    await ServiceRequest.deleteMany({ email: user.email });
    // Delete the user
    await User.deleteOne({ _id: req.userId });
    res.clearCookie("token");
    await sendAccountDeletionEmail(user.email, user.name);
    res
      .status(200)
      .json({ success: true, message: "Account and all related data deleted successfully" });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Get current user's account details
export const getMyAccountDetails = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.status(200).json({
      success: true,
      accountDetails: {
        name: user.name,
        accountNumber: user.accountNumber,
        ifscCode: user.ifscCode,
        balance: user.balance
      }
    });
  } catch (error) {
    console.error("Error getting account details:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Find user by account number
export const findUserByAccountNumber = async (req, res) => {
  try {
    const { accountNumber } = req.params;
    
    if (!accountNumber) {
      return res.status(400).json({
        success: false,
        message: "Account number is required"
      });
    }

    const user = await User.findOne({ accountNumber }).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found with this account number"
      });
    }

    res.status(200).json({
      success: true,
      user: {
        name: user.name,
        accountNumber: user.accountNumber,
        ifscCode: user.ifscCode
      }
    });
  } catch (error) {
    console.error("Error finding user by account number:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const verifyTwoFactorAuth = async (req, res) => {
  const { email, verificationCode } = req.body;
  try {
    if (!email || !verificationCode) {
      return res.status(400).json({
        success: false,
        message: "Email and verification code are required!",
      });
    }

    const user = await User.findOne({
      email,
      verificationToken: verificationCode,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }

    // Clear the verification token
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();

    // Generate token and set cookie
    generateTokenAndSetCookie(res, user._id);

    res.status(200).json({
      success: true,
      message: "Two-factor authentication completed successfully",
      user: {
        ...user._doc,
        password: undefined,
        trustedIPs: undefined,
        trustedDevices: undefined,
        locations: undefined,
        behavioralProfile: undefined,
        riskScore: undefined,
      },
    });
  } catch (error) {
    console.log("Error verifying two-factor authentication:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Reset riskScore to 0 for the authenticated user (with conditions)
export const resetRiskScore = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    // Only allow reset if riskScore is greater than 0
    if (user.riskScore <= 0) {
      return res.status(400).json({ success: false, message: "Risk score is already 0." });
    }
    // You can add more conditions here if needed (e.g., cooldown, admin approval, etc.)
    user.riskScore = 0;
    await user.save();
    return res.status(200).json({ success: true, message: "Risk score reset to 0." });
  } catch (error) {
    console.error("Error resetting risk score:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};
