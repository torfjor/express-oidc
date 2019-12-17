import express from "express";
import session from "express-session";
import dotenv from "dotenv";
import mongoStore from "connect-mongo";
import bodyParser from "body-parser";
import createError from "http-errors";
import { OIDCClient } from "./lib/Client";

const isDev = process.env.NODE_ENV === "development";

if (isDev) {
  const parsed = dotenv.config();
  if (parsed.error) throw parsed.error;
}

const dbUrl = process.env.DB_URL;
if (!dbUrl) throw new Error("failed to get db URL from environment");
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret)
  throw new Error("failed to get session secret from environment");
const successRedirect = process.env.SUCCESS_REDIRECT;
if (!successRedirect) {
  throw new Error("failed to get redirect urls from environment");
}

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
app.use(bodyParser.urlencoded({ extended: true }));

(async () => {
  const issuerHost = process.env.OPENID_ENDPOINT || "";
  const client = await OIDCClient.Create(
    {
      client_id: process.env.OPENID_CLIENT_ID || "",
      client_secret: process.env.OPENID_CLIENT_SECRET || "",
      redirect_uris: [process.env.OPENID_REDIRECT_URL || ""],
      response_types: ["code"],
      scopes: process.env.OPENID_SCOPES || "openid"
    },
    issuerHost
  );

  // Middleware
  const ensureSession: express.Handler = (req, res, next) => {
    if (!req.session) return next(createError(400, "no session"));
    return next();
  };

  // Handlers
  app.get("/auth/token", ensureSession, async (req, res, next) => {
    const { code, state } = req.query;

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
