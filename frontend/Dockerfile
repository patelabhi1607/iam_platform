# ---- Build stage: compile the React app with Vite ----
FROM node:20-alpine AS build

WORKDIR /app

# Install deps first (better layer caching)
COPY package*.json ./
RUN npm install

# Vite bakes env vars at build time, so the API URL must be present now.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL

COPY . .
RUN npm run build

# ---- Runtime stage: serve the static build with nginx ----
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
