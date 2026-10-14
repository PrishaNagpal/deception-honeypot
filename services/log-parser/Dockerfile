FROM node:22-alpine

WORKDIR /app

# Install only runtime dependencies (pg), exactly as locked in package-lock.json.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src

ENV NODE_ENV=production

# The image's built-in unprivileged user (UID 1000). It owns the Flask and
# Dionaea logs, and Cowrie's logs are readable by everyone. All log mounts are
# read-only in docker-compose.yml.
USER node

# No ports: the parser only reads files and connects out to hp-db.
CMD ["node", "src/index.js"]
