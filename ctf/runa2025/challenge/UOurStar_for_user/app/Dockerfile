FROM node:18-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libatspi2.0-0 libdrm2 libgbm1 libgtk-3-0 \
    libnss3 libx11-xcb1 libxcomposite1 libxdamage1 \
    libxfixes3 libxkbcommon0 libxrandr2 libxshmfence1 \
    libxcb1 libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

ENV NODE_ENV=production \
    TZ=Asia/Seoul \
    PUPPETEER_CACHE_DIR=/home/node/.cache/puppeteer

COPY . .

COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev \
    && npm cache clean --force

RUN mkdir -p /home/node/.cache && chown -R node:node /home/node /usr/src/app

USER node

EXPOSE 5000

CMD ["node", "app.js"]