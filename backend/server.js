import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import rateLimit from "express-rate-limit";

import { supabaseAdmin } from "./src/supabaseAdmin.js";
import healthRoute from "./src/routes/health.js";
import claudeRoute from "./src/routes/claude.js";
import validateRoute from "./src/routes/validate.js";
import webhookRoute from "./src/routes/webhook.js";
import blindspotRoute from "./src/routes/blindspot.js";
import { makeDemoLimiter } from "./src/rateLimiter.js";
import { budgetLimiter } from "./src/budgetLimiter.js";

const app = express();

// Cloudflare sits in front of this in production — required for
// express-rate-limit to see real client IPs rather than Cloudflare's.
app.set("trust proxy", 1);

app.use(helmet());
app.use(morgan("combined"));
app.use(express.json({ limit: "50kb" }));

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean);
app.use(
  cors({
    origin: allowedOrigins.length ? allowedOrigins : true,
  })
);

// Attaches req.user from the Supabase JWT sent by the frontend, if present.
async function attachUser(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return next();
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (!error && data?.user) req.user = data.user;
  next();
}
app.use(attachUser);

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const claudeLimiter = rateLimit({ windowMs: 60 * 1000, max: 15 });
app.use(globalLimiter);

const demoLimiter = makeDemoLimiter(supabaseAdmin);

app.use("/api/health", healthRoute);
app.use("/api/claude", claudeLimiter, demoLimiter, budgetLimiter, claudeRoute);
app.use("/api/validate", claudeLimiter, demoLimiter, validateRoute);
app.use("/api/blindspot", claudeLimiter, demoLimiter, blindspotRoute);
app.use("/api/webhook", webhookRoute);

// Safe, no-internals-leaked error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`DetectIQ backend listening on :${port}`));
