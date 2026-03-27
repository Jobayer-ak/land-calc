import cors from 'cors';
import dotenv from 'dotenv';
import express, { Application } from 'express';
import { errorHandler } from './middleware/error.middleware';
import authRoutes from './routes/auth.route';
import landRoutes from './routes/land.route';
import connectDB from './utils/database';

dotenv.config();

const app: Application = express();

// CORS configuration
const allowedOrigins =
  process.env.NODE_ENV === 'production'
    ? [
        process.env.FRONTEND_URL || 'https://your-frontend.vercel.app',
        'https://your-domain.com',
      ]
    : ['http://localhost:3000', 'http://localhost:3001'];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to database
connectDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/land', landRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
  });
});

// Root endpoint
app.get('/api', (req, res) => {
  res.json({
    message: 'Land Calculator API is running',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      land: '/api/land',
      health: '/api/health',
    },
  });
});

// Error handler (must be last)
app.use(errorHandler);

// For local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV}`);
  });
}

// Export for Vercel serverless function
export default app;
