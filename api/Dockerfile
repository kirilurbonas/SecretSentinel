FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
RUN addgroup -g 1000 sentinel && adduser -u 1000 -G sentinel -D sentinel
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
USER sentinel
ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "dist/index.js"]
