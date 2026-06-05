require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const REPORT_DIR = process.env.REPORT_DIR || path.join(__dirname, "reports");
const allowedEmails = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

if (!fs.existsSync(REPORT_DIR)) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
}

app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value?.toLowerCase();

      if (!email) {
        return done(null, false);
      }

      if (!allowedEmails.includes(email)) {
        return done(null, false);
      }

      return done(null, {
        id: profile.id,
        name: profile.displayName,
        email,
      });
    }
  )
);

function requireLogin(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.redirect("/login");
}

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/reports/latest.html");
  }

  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.send(`
    <html>
      <body>
        <h2>Weekly Report Login</h2>
        <a href="/auth/google">Login with Google</a>
      </body>
    </html>
  `);
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/forbidden",
  }),
  (req, res) => {
    res.redirect("/reports/latest.html");
  }
);

app.get("/forbidden", (req, res) => {
  res.status(403).send("Access denied.");
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

app.use(
  "/reports",
  requireLogin,
  express.static(REPORT_DIR)
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});