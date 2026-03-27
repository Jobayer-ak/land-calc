// src/routes/auth.route.ts
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';

const router = Router();

// Public routes
router.post('/signup', AuthController.register);
router.post('/signin', AuthController.login);

// Admin routes
router.get('/users', AuthController.getAllUsers);
router.put('/activate/:userId', AuthController.activateUser);
router.put('/reset-device/:userId', AuthController.resetDevice); // Reset device registration

// Protected routes
router.get('/profile', authenticate, AuthController.getProfile);
router.get('/verify', authenticate, AuthController.verifyToken);
router.post('/refresh', authenticate, AuthController.refreshToken);
router.post('/logout', authenticate, AuthController.logout);

export default router;
