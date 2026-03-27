// src/utils/jwt.ts
import jwt from 'jsonwebtoken';

interface TokenPayload {
  userId: string;
  email: string;
  deviceFingerprint?: string;
}

export const generateToken = (payload: TokenPayload): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  console.log('🔵 Generating token with payload:', {
    userId: payload.userId,
    email: payload.email,
    hasDeviceFingerprint: !!payload.deviceFingerprint,
  });

  return jwt.sign(payload, secret, {
    expiresIn: '7d',
  });
};

export const verifyToken = (token: string): TokenPayload => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  const decoded = jwt.verify(token, secret) as TokenPayload;
  console.log('🔵 Decoded token:', {
    userId: decoded.userId,
    email: decoded.email,
    hasDeviceFingerprint: !!decoded.deviceFingerprint,
  });

  return decoded;
};
