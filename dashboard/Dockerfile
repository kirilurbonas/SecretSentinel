FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
RUN addgroup -g 1000 app && adduser -u 1000 -G app -D app
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
RUN chown -R app:app /usr/share/nginx/html
USER app
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
