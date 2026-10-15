FROM node:22-alpine
WORKDIR /app
COPY package.json server.js runtime.mjs worker-pro.js ./
ENV NODE_ENV=production
ENV DB_PATH=/data/panel.db
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
