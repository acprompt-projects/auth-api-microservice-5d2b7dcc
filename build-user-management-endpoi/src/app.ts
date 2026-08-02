import express from 'express';
import authRoutes from './routes/auth.routes';

const app = express();

app.use(express.json());

// Mount auth routes
app.use('/auth', authRoutes);

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

export default app;