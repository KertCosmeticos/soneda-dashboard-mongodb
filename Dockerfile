FROM node:20-alpine

WORKDIR /app

COPY backend/package*.json ./backend/

RUN cd backend && npm install --omit=dev

COPY backend ./backend
COPY frontend ./frontend

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "backend/src/server.js"]
