// Centralised logger — Week 3 Task 2.
// Writes structured JSON lines to `security.log` and pretty text to stdout.

const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-management' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(
          ({ timestamp, level, message, ...meta }) =>
            `${timestamp} [${level}] ${message} ${
              Object.keys(meta).length && meta.service ? '' : JSON.stringify(meta)
            }`
        )
      ),
    }),
    new winston.transports.File({ filename: 'security.log' }),
  ],
});

module.exports = logger;
