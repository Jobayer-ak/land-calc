// src/controllers/auth.controller.ts
import { Request, Response } from 'express';
import { User } from '../models/user.model';
import {
  generateDeviceFingerprint,
  getCompleteDeviceInfo,
} from '../utils/device';
import { generateToken, verifyToken } from '../utils/jwt';

export class AuthController {
  static async register(req: Request, res: Response) {
    try {
      console.log('🔵 Registration started');
      console.log('Request body:', req.body);

      const {
        fullName,
        email,
        password,
        confirmPassword,
        mobileNumber,
        address,
      } = req.body;

      // Validate required fields
      if (
        !fullName ||
        !email ||
        !password ||
        !confirmPassword ||
        !mobileNumber ||
        !address
      ) {
        return res.status(400).json({
          success: false,
          message: 'All fields are required',
        });
      }

      // Check if passwords match
      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      // Check if user exists
      const existingUser = await User.findOne({
        $or: [{ email }, { mobileNumber }],
      });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or mobile number already exists',
        });
      }

      // Create user
      const user = new User({
        fullName,
        email,
        password,
        mobileNumber,
        address,
        isActive: false,
      });

      await user.save();
      console.log('✅ User saved:', user._id);

      res.status(201).json({
        success: true,
        message:
          'User registered successfully. Please wait for admin approval.',
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
        },
      });
    } catch (error: any) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  // src/controllers/auth.controller.ts - Login function
  static async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      // Get device information
      const userAgent = req.headers['user-agent'] || 'Unknown';
      const ip = req.ip || req.socket.remoteAddress || 'Unknown';
      const acceptLanguage = req.headers['accept-language'];

      const deviceFingerprint = generateDeviceFingerprint(
        userAgent,
        ip,
        acceptLanguage,
      );
      const deviceInfo = getCompleteDeviceInfo(userAgent);

      const user = await User.findOne({ email }).select(
        '+password +registeredDeviceFingerprint',
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      // Check if account is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const minutesLeft = Math.ceil(
          (user.lockedUntil.getTime() - Date.now()) / 60000,
        );
        return res.status(403).json({
          success: false,
          message: `Account is locked. Please try again in ${minutesLeft} minutes.`,
        });
      }

      // Check if user is active
      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated. Please contact admin.',
        });
      }

      // Verify password
      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        user.loginAttempts = (user.loginAttempts || 0) + 1;

        if (user.loginAttempts >= 5) {
          user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
          await user.save();
          return res.status(403).json({
            success: false,
            message: 'Too many failed attempts. Account locked for 30 minutes.',
          });
        }

        await user.save();
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
          remainingAttempts: 5 - user.loginAttempts,
        });
      }

      // Device registration logic
      if (!user.registeredDeviceFingerprint) {
        // First login - register this device
        console.log('📱 First login - Registering device');
        user.registeredDeviceFingerprint = deviceFingerprint;
        user.registeredDeviceInfo = JSON.stringify(deviceInfo);
        user.registeredDeviceId = deviceFingerprint.substring(0, 32);
        await user.save();
        console.log('✅ Device registered successfully');
      } else if (user.registeredDeviceFingerprint !== deviceFingerprint) {
        // Different device - deny login (you can comment this out for testing)
        console.log('❌ Device mismatch!');
        const registeredDevice = JSON.parse(user.registeredDeviceInfo || '{}');
        return res.status(403).json({
          success: false,
          message: 'This device is not registered for this account.',
          error: 'DEVICE_NOT_REGISTERED',
          registeredDevice: registeredDevice,
          currentDevice: deviceInfo,
        });
      } else {
        console.log('✅ Device fingerprint matches!');
      }

      // Reset login attempts on successful login
      user.loginAttempts = 0;
      user.lockedUntil = undefined;
      user.lastLoginAt = new Date();
      user.lastLoginDevice = deviceInfo.deviceType;
      await user.save();

      // Generate JWT token with device fingerprint
      const token = generateToken({
        userId: user._id.toString(),
        email: user.email,
        deviceFingerprint: user.registeredDeviceFingerprint, // Include the stored fingerprint
      });

      console.log(
        '✅ Login successful! Token generated with device fingerprint',
      );

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
          registeredDevice: user.registeredDeviceInfo
            ? JSON.parse(user.registeredDeviceInfo)
            : null,
          lastLoginAt: user.lastLoginAt,
          lastLoginDevice: user.lastLoginDevice,
        },
      });
    } catch (error: any) {
      console.error('❌ Login error:', error);
      console.error('Error stack:', error.stack);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }
  // src/controllers/auth.controller.ts
  static async verifyToken(req: Request, res: Response) {
    try {
      console.log('🔵 Backend - Verify token called');

      const authHeader = req.headers.authorization;
      console.log('🔵 Auth header:', authHeader ? 'Present' : 'Missing');

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No token provided');
        return res.status(401).json({
          success: false,
          message: 'No token provided',
        });
      }

      const token = authHeader.split(' ')[1];
      console.log('🔵 Token received, length:', token.length);

      let decoded;
      try {
        decoded = verifyToken(token);
        console.log('✅ Token decoded successfully:', {
          userId: decoded.userId,
          email: decoded.email,
          hasDeviceFingerprint: !!decoded.deviceFingerprint,
        });
      } catch (error: any) {
        console.log('❌ Token verification failed:', error.message);
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired token',
        });
      }

      // Make sure we have userId
      if (!decoded.userId) {
        console.log('❌ No userId in token');
        return res.status(401).json({
          success: false,
          message: 'Invalid token payload',
        });
      }

      // Find user - don't select password, but do select registeredDeviceFingerprint
      const user = await User.findById(decoded.userId).select('-password');

      console.log('🔵 User found:', !!user);

      if (!user) {
        console.log('❌ User not found for ID:', decoded.userId);
        return res.status(401).json({
          success: false,
          message: 'User not found',
        });
      }

      // Check if user is active
      if (!user.isActive) {
        console.log('❌ User not active');
        return res.status(403).json({
          success: false,
          message: 'Account is not activated',
        });
      }

      // If we have device fingerprint in token, verify it (but make it optional for now)
      if (decoded.deviceFingerprint && user.registeredDeviceFingerprint) {
        console.log('🔵 Checking device fingerprint...');
        console.log('Stored:', user.registeredDeviceFingerprint);
        console.log('Token:', decoded.deviceFingerprint);

        if (user.registeredDeviceFingerprint !== decoded.deviceFingerprint) {
          console.log('❌ Device mismatch');
          return res.status(401).json({
            success: false,
            message: 'Session expired. Device verification failed.',
            code: 'DEVICE_MISMATCH',
          });
        }
        console.log('✅ Device fingerprint matches');
      } else {
        console.log(
          '⚠️ Skipping device check - no fingerprint in token or user',
        );
      }

      console.log('✅ All checks passed, token is valid');

      res.json({
        success: true,
        message: 'Token is valid',
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
        },
      });
    } catch (error: any) {
      console.error('❌ Token verification error:', error);
      console.error('Error stack:', error.stack);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  static async logout(req: Request, res: Response) {
    try {
      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          message: 'Unauthorized',
        });
      }

      const user = await User.findById(userId).select('-password');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      res.json({
        success: true,
        user,
      });
    } catch (error) {
      console.error('Profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  // ✅ Admin endpoint to reset device for a user
  static async resetDevice(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      user.registeredDeviceFingerprint = undefined;
      user.registeredDeviceInfo = undefined;
      user.registeredDeviceId = undefined;
      user.loginAttempts = 0;
      user.lockedUntil = undefined;
      await user.save();

      res.json({
        success: true,
        message:
          'Device registration reset successfully. User can now login from any device.',
      });
    } catch (error) {
      console.error('Reset device error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async activateUser(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (user.isActive) {
        return res.status(400).json({
          success: false,
          message: 'User is already active',
        });
      }

      user.isActive = true;
      await user.save();

      res.json({
        success: true,
        message: 'User activated successfully',
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          isActive: user.isActive,
        },
      });
    } catch (error: any) {
      console.error('Activation error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          message: 'No token provided',
        });
      }

      const oldToken = authHeader.split(' ')[1];

      let decoded;
      try {
        decoded = verifyToken(oldToken);
      } catch (error) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired token',
        });
      }

      const user = await User.findById(decoded.userId).select(
        '+registeredDeviceFingerprint',
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found',
        });
      }

      // Check if user is active
      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated',
        });
      }

      // Verify device fingerprint
      if (
        !user.registeredDeviceFingerprint ||
        user.registeredDeviceFingerprint !== decoded.deviceFingerprint
      ) {
        return res.status(401).json({
          success: false,
          message: 'Device mismatch. Please login again.',
        });
      }

      const newToken = generateToken({
        userId: user._id.toString(),
        email: user.email,
        deviceFingerprint: user.registeredDeviceFingerprint,
      });

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        token: newToken,
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
        },
      });
    } catch (error: any) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getAllUsers(req: Request, res: Response) {
    try {
      const users = await User.find().select('-password');

      res.json({
        success: true,
        count: users.length,
        users,
      });
    } catch (error: any) {
      console.error('Get all users error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
