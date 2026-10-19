
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const pool = require("./db/pool");
const { body, validationResult } = require("express-validator");
const crypto = require('node:crypto');


const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "development-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());


function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/log-in')
  }

  next()
}

function requireMember(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/log-in')
  }

  if (!req.user.is_member) {
    return res.redirect('/join-club')
  }

  next()
}

function requireAdmin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/log-in');
  }

  if (req.user.is_admin !== true) {
    return res.status(403).send('Forbidden: Admin access required.');
  }

  next();
}


// Home page
app.get('/', async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT
        messages.id,
        messages.title,
        messages.text,
        messages.created_at,
        users.username
      FROM messages
      JOIN users ON users.id = messages.user_id
      ORDER BY messages.created_at DESC
    `)

    res.render('index', {
      messages: result.rows,
      user: req.user || null
    })
  } catch (err) {
    next(err)
  }
})

// Sign-up page
app.get("/sign-up", (req, res) => {
  res.render("sign-up", { errors: [], formData: {} });
});

// Handle sign-up form
app.post(
  "/sign-up",
  body("username")
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be 3–30 characters.")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username may contain letters, numbers and underscores only."),

  body("email")
    .trim()
    .isEmail()
    .withMessage("Enter a valid email address.")
    .normalizeEmail()
    .isLength({ max: 255 })
    .withMessage("Email must be no longer than 255 characters."),

  body("password")
    .isString()
    .isLength({ min: 12, max: 72 })
    .withMessage("Password must be 12–72 characters."),

  body("confirmPassword")
    .custom((value, { req }) => value === req.body.password)
    .withMessage("Passwords do not match."),

  async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).render("sign-up", {
        errors: errors.array(),
        formData: {
          username: req.body.username,
          email: req.body.email,
        },
      });
    }

    try {
      const { username, email, password } = req.body;
      const password_hash = await bcrypt.hash(password, 10);

      await pool.query(
        `INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, $3)`,
        [username, email, password_hash]
      );

      // Redirect after successful registration.
      return res.redirect("/log-in?registered=1");
    } catch (error) {
      // PostgreSQL unique-constraint violation.
      if (error.code === "23505") {
        return res.status(409).render("sign-up", {
          errors: [
            { msg: "That username or email is already registered." },
          ],
          formData: {
            username: req.body.username,
            email: req.body.email,
          },
        });
      }

      return next(error);
    }
  }
);

// Passport username/password authentication
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );

      const user = rows[0];

    console.log("Username received:", username);
    console.log("Password received:", typeof password);
    console.log("User found:", Boolean(user));
    console.log(
        "Available user columns:",
    user ? Object.keys(user) : "No user found"
);


      if (!user) {
        return done(null, false, {
          message: "Incorrect username or password.",
        });
      }

      console.log("Hash exists:", Boolean(user.password_hash));

      const matches = await bcrypt.compare(password, user.password_hash);

      if (!matches) {
        return done(null, false, {
          message: "Incorrect username or password.",
        });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

// Store the user's ID in the session.
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Retrieve the user on subsequent requests.
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, email, is_member, is_admin FROM users WHERE id = $1",
      [id]
    );

    if (!rows[0]) {
      return done(null, false);
    }

    return done(null, rows[0]);
  } catch (error) {
    return done(error);
  }
});

// Login page
app.get("/log-in", (req, res) => {
  res.render("log-in", {
    error: null,
    registered: req.query.registered === "1",
  });
});

// Handle login
app.post('/log-in', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err)

    if (!user) {
      console.log('Login failed:', info?.message)
      return res.status(401).render('log-in', {
        error: 'Incorrect email or password.'
      })
    }

    req.session.regenerate((err) => {
      if (err) return next(err)

      req.logIn(user, (err) => {
        if (err) return next(err)

        console.log('Login successful for user ID:', user.id)
        res.redirect('/')
      })
    })
  })(req, res, next)
})

// Log out
app.post("/log-out", (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    }

    req.session.destroy((sessionError) => {
      if (sessionError) {
        return next(sessionError);
      }

      res.clearCookie("connect.sid");
      return res.redirect("/");
    });
  });
});


app.get('/join-club', requireAuth, (req, res) => {
    if(req.user.is_member) {
        return res.redirect('/')
    }

    res.render('join-club', { error: null })
})

app.post('/join-club', requireAuth, async (req, res, next) => {
    try {
        const submitted = req.body.passcode
        const expected = process.env.CLUB_PASSCODE

        if (!expected) {
            return res.status(500).send("Club passcode is not configured.");
            }

        if (typeof submitted !== 'string' ||
            typeof expected !== 'string' ||
            !expected.length)  {
                return res.status(400).render('join-club', {
                    error: 'Unable to verify the passcode'
                })
            }
            const submittedBuffer = Buffer.from(submitted || "")
            const expectedBuffer = Buffer.from(expected)

            const valid =
                submittedBuffer.length === expectedBuffer.length && 
                crypto.timingSafeEqual(submittedBuffer, expectedBuffer)

                if (!valid) {
                    return res.status(400).render('join-club', {
                        error: 'Incorrect passcode. Please try again'
                    })
                }

                await pool.query(
                    'UPDATE users SET is_member = TRUE WHERE id = $1',
                    [req.user.id]
                )

                res.redirect('/')
    } catch (err) {
        next(err)
    }
})


// Admin passcode page
app.get('/admin-page', requireAuth, (req, res) => {
  if (req.user.is_admin) {
    return res.redirect('/');
  }

  res.render('admin-page', { error: null });
});

// Verify admin passcode
app.post('/admin-page', requireAuth, async (req, res, next) => {
  try {
    const submitted = req.body.passcode;
    const expected = process.env.ADMIN_PASSCODE;

    if (!expected) {
      return res.status(500).send(
        'Admin passcode is not configured.'
      );
    }

    if (typeof submitted !== 'string') {
      return res.status(400).render('admin-page', {
        error: 'Unable to verify the passcode.'
      });
    }

    const submittedBuffer = Buffer.from(submitted);
    const expectedBuffer = Buffer.from(expected);

    const valid =
      submittedBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(submittedBuffer, expectedBuffer);

    if (!valid) {
      return res.status(400).render('admin-page', {
        error: 'Incorrect passcode. Please try again.'
      });
    }

    await pool.query(
      'UPDATE users SET is_admin = TRUE WHERE id = $1',
      [req.user.id]
    );

    return res.redirect('/');
  } catch (err) {
    next(err);
  }
});

// Delete a message (admins only)
app.post(
  '/messages/:id/delete',
  requireAdmin,
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).send('Invalid message ID.');
      }

      const result = await pool.query(
        'DELETE FROM messages WHERE id = $1',
        [id]
      );

      if (result.rowCount === 0) {
        return res.status(404).send('Message not found.');
      }

      return res.redirect('/');
    } catch (err) {
      next(err);
    }
  }
);




app.get('/new-message', requireAuth, (req, res) => {
    res.render('new-message', { error: null })
})
app.post(
  '/new-message',
  requireAuth,

  body('title')
    .trim()
    .isLength({ min: 1, max: 150 })
    .withMessage('Title must be 1-150 characters.'),

  body('text')
    .trim()
    .isLength({ min: 1, max: 10000 })
    .withMessage('Message must be 1-10,000 characters.'),

  async (req, res, next) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).render('new-message', {
        error: errors.array()[0].msg
      })
    }

    try {
      await pool.query(
        `INSERT INTO messages (title, text, user_id)
         VALUES ($1, $2, $3)`,
        [
          req.body.title,
          req.body.text,
          req.user.id
        ]
      )

      res.redirect('/')
    } catch (err) {
      next(err)
    }
  }
)

// Error handler
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).send("Something went wrong. Check the server terminal.");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
});
