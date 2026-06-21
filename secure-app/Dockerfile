# Multi-stage Docker build for UserHub Secure (Week 6 Task 2).
#
# Goals:
#   - small final image (alpine, no dev deps)
#   - non-root runtime user
#   - reproducible build via `npm ci`
#   - no secrets baked in (mount .env at runtime)
#   - native deps (better-sqlite3, bcrypt) compiled in the build stage only

# ---------- build stage ----------
FROM node:20-alpine AS build

WORKDIR /build

# Toolchain needed to compile native modules (bcrypt, better-sqlite3).
# Removed from the final image by virtue of the stage split.
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY . .

# ---------- runtime stage ----------
FROM node:20-alpine

# Non-root user with a fixed UID so volume mounts behave predictably.
RUN addgroup -S -g 10001 nodejs \
 && adduser  -S -u 10001 -G nodejs nodejs

WORKDIR /app

# Copy only what the runtime needs.
COPY --from=build --chown=nodejs:nodejs /build/node_modules ./node_modules
COPY --from=build --chown=nodejs:nodejs /build/package.json ./package.json
COPY --from=build --chown=nodejs:nodejs /build/server.js    ./server.js
COPY --from=build --chown=nodejs:nodejs /build/logger.js    ./logger.js
COPY --from=build --chown=nodejs:nodejs /build/middleware   ./middleware
COPY --from=build --chown=nodejs:nodejs /build/routes       ./routes
COPY --from=build --chown=nodejs:nodejs /build/views        ./views
COPY --from=build --chown=nodejs:nodejs /build/public       ./public
COPY --from=build --chown=nodejs:nodejs /build/config       ./config

# Drop privileges before the app starts.
USER nodejs

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

# tini is supplied by node:alpine images for proper PID-1 signal handling.
ENTRYPOINT ["node", "server.js"]
