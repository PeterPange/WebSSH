FROM node:20-bookworm-slim

WORKDIR /app

# better-sqlite3 may need to compile when no matching prebuilt binary exists.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY public ./public

RUN mkdir -p /data && chown -R node:node /app /data

ENV PORT=9998
ENV WEBSSH_DATA_DIR=/data
EXPOSE 9998

USER node
CMD ["node", "server.js"]
