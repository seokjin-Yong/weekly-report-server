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
const UPLOAD_API_KEY = process.env.UPLOAD_API_KEY;

const allowedEmails = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

if (!fs.existsSync(REPORT_DIR)) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
}

app.set("trust proxy", 1);

// JSON Body를 req.body로 파싱하기 위한 미들웨어
// 반드시 app.post("/api/upload", ...)보다 위에 있어야 합니다.
app.use(express.json({ limit: "20mb" }));

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

function requireUploadApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!UPLOAD_API_KEY) {
    return res.status(500).json({
      success: false,
      error: "UPLOAD_API_KEY is not configured.",
    });
  }

  if (apiKey !== UPLOAD_API_KEY) {
    return res.status(401).json({
      success: false,
      error: "Invalid API key.",
    });
  }

  return next();
}

function isSafeHtmlFilename(filename) {
  return /^[a-zA-Z0-9._-]+\.html$/.test(filename);
}

function getLatestReportFile() {
  const files = fs
    .readdirSync(REPORT_DIR)
    .filter((file) => file.endsWith(".html"))
    .sort()
    .reverse();

  return files[0] || null;
}

app.get("/", requireLogin, (req, res) => {
  const latestFile = getLatestReportFile();

  if (!latestFile) {
    return res.send("No reports found.");
  }

  return res.redirect(`/reports/${latestFile}`);
});

app.get("/login", (req, res) => {
  res.sendFile( path.join(__dirname, 'login.html') );;
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
    res.redirect("/");
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

app.post("/api/upload", requireUploadApiKey, (req, res) => {
  const { filename, html } = req.body;

  if (!filename || !html) {
    return res.status(400).json({
      success: false,
      error: "filename and html are required.",
    });
  }

  if (!isSafeHtmlFilename(filename)) {
    return res.status(400).json({
      success: false,
      error: "Invalid filename. Only .html files are allowed.",
    });
  }

  const filePath = path.join(REPORT_DIR, filename);

  fs.writeFileSync(filePath, html, "utf8");

  return res.json({
    success: true,
    filename,
    url: `/reports/${filename}`,
  });
});

app.get("/api/reports", requireLogin, (req, res) => {
  const files = fs
    .readdirSync(REPORT_DIR)
    .filter((file) => file.endsWith(".html"))
    .sort()
    .reverse();

  res.json({
    success: true,
    reports: files.map((file) => ({
      filename: file,
      url: `/reports/${file}`,
    })),
  });
});

app.use("/reports", requireLogin, express.static(REPORT_DIR));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});