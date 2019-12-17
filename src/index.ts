import express from "express";
import session from "express-session";
import dotenv from "dotenv";
import mongoStore from "connect-mongo";
import bodyParser from "body-parser";
import createError from "http-errors";
import { OIDCClient } from "./lib/Strategy";

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

  // Handlers
  app.get("/auth/token", async (req, res, next) => {
    try {
      const token = await client.login(req);

      return res.json(token.id_token);
    } catch (error) {
      return next(createError(401, error));
    }
  });

  app.get("/auth/login", (req, res, next) => {
    try {
      const url = client.authenticate(req);

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
