import express, { Handler } from "express";
import passport from "passport";
import session from "express-session";
import dotenv from "dotenv";
import mongoStore from "connect-mongo";
import bodyParser from "body-parser";
import { OIDCStrategy } from "./lib/Strategy";
import { parentPort } from "worker_threads";

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

const app = express();
const Store = mongoStore(session);

app.set("trust proxy", true);
app.use(
  session({
    store: new Store({ url: dbUrl }),
    secret: sessionSecret,
    saveUninitialized: false,
    resave: false,
    cookie: {
      secure: !isDev
    }
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware
const ensureAuthenticated: express.Handler = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect("/auth/fail");
};

// Handlers
app.get(
  "/callback",
  passport.authenticate("passport-openid-connect", {
    successReturnToOrRedirect: "/auth/success",
    failureRedirect: "/auth/fail"
  })
);

app.get("/auth/login", (req, res, next) => {
  passport.authenticate("passport-openid-connect")(req, res);
});

app.get("/auth/success", ensureAuthenticated, (req, res) => {
  res.json({
    user: req.user,
    token: req.session ? req.session.token : undefined
  });
});

app.get("/auth/logout", (req, res) => {
  req.logout();
  res.redirect("https://app.divein.no");
});

app.get("/auth/fail", (req, res) => {
  res.status(401).json({ error: "Failed to login" });
});

// Listen and serve
(async () => {
  const issuerHost = process.env.OPENID_ENDPOINT || "";
  const vippsStrategy = await OIDCStrategy.Create(
    {
      client_id: process.env.OPENID_CLIENT_ID || "",
      client_secret: process.env.OPENID_CLIENT_SECRET || "",
      redirect_uris: [process.env.OPENID_REDIRECT_URL || ""],
      response_types: ["code"],
      scopes: process.env.OPENID_SCOPES || "openid"
    },
    issuerHost
  );
  passport.use(vippsStrategy);

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`server listening on ${port}`);
  });
})();
