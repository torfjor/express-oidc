import express from "express";
import session from "express-session";
import cors from "cors";
import dotenv from "dotenv";
import mongoStore from "connect-mongo";
import createError from "http-errors";

import { isDev, ensureEnv } from "./helpers";
import { OIDCClient } from "./lib/Client";

if (isDev) {
  const parsed = dotenv.config();
  if (parsed.error) throw parsed.error;
}

const [
  dbUrl,
  sessionSecret,
  issuerHost,
  client_id,
  client_secret,
  redirect_uris,
  scopes
] = ensureEnv([
  "DB_URL",
  "SESSION_SECRET",
  "OPENID_ENDPOINT",
  "OPENID_CLIENT_ID",
  "OPENID_CLIENT_SECRET",
  "OPENID_REDIRECT_URL",
  "OPENID_SCOPES"
]);

const app = express();
const Store = mongoStore(session);

app.set("trust proxy", true);
app.use(
  session({
    store: new Store({ url: dbUrl, ttl: 60 }),
    secret: sessionSecret,
    saveUninitialized: false,
    resave: false,
    cookie: {
      secure: !isDev
    }
  })
);

// Middleware
const ensureSession: express.Handler = (req, res, next) => {
  if (!req.session) return next(createError(400, "no session"));
  return next();
};

(async () => {
  const client = await OIDCClient.Create(
    {
      client_id,
      client_secret,
      scopes,
      redirect_uris: [redirect_uris],
      response_types: ["code"]
    },
    issuerHost
  );

  // Handlers
  app.use(
    "/auth",
    cors({
      origin: [
        "https://app.divein.no",
        "http://localhost:8080",
        "http://127.0.0.1:8080"
      ]
    })
  );
  app.get("/auth/token", ensureSession, async (req, res, next) => {
    const { code, state } = req.query;

    // Middleware ensures session is set,
    if (!req.session!.state) {
      return next(createError(400, "session missing state"));
    }
    const savedState = req.session!.state;

    try {
      const token = await client.login(code, state, savedState);
      return res.json(token);
    } catch (error) {
      return next(createError(401, error));
    }
  });

  app.get("/auth/login", ensureSession, (req, res, next) => {
    try {
      const { url, state } = client.authenticate(req);

      // Middleware ensures session is set,
      req.session!.state = state;

      return res.redirect(url);
    } catch (error) {
      return next(createError(500, error));
    }
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`server listening on ${port}`);
  });
})();
