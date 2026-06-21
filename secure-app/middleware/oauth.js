// Google OAuth 2.0 scaffold via passport-google-oauth20.
//
// This is wired up but the strategy is only registered when both
// GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are present. The intent is to
// satisfy the "API keys OR OAuth" requirement by demonstrating both options:
// API keys for machine-to-machine on /api/*, OAuth for user sign-in.

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const logger = require('../logger');

function configureOAuth(db, BCRYPT_COST, bcrypt) {
  const clientID = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const callbackURL = process.env.GOOGLE_CALLBACK_URL;

  if (!clientID || !clientSecret) {
    logger.info('Google OAuth not configured — set GOOGLE_CLIENT_ID/SECRET to enable');
    return { enabled: false };
  }

  passport.use(
    new GoogleStrategy(
      { clientID, clientSecret, callbackURL },
      (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0] && profile.emails[0].value;
          if (!email) return done(new Error('Google profile missing email'));

          // Find or create local user record keyed off the Google email.
          let user = db.prepare('SELECT id, username, email, bio FROM users WHERE email = ?').get(email);
          if (!user) {
            // Generate a deterministic username from the profile.
            const base = (profile.displayName || email.split('@')[0])
              .toLowerCase()
              .replace(/[^a-z0-9]/g, '')
              .slice(0, 24) || `user${Date.now()}`;
            const randomPwHash = bcrypt.hashSync(
              require('crypto').randomBytes(32).toString('hex'),
              BCRYPT_COST
            );
            const result = db
              .prepare('INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)')
              .run(base, email, randomPwHash, '');
            user = { id: result.lastInsertRowid, username: base, email, bio: '' };
            logger.info('OAuth user created', { userId: user.id, provider: 'google' });
          } else {
            logger.info('OAuth user logged in', { userId: user.id, provider: 'google' });
          }
          done(null, user);
        } catch (e) {
          done(e);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    const u = db.prepare('SELECT id, username, email, bio FROM users WHERE id = ?').get(id);
    done(null, u || null);
  });

  return { enabled: true };
}

module.exports = { configureOAuth, passport };
