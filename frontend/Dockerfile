# Builds the React app and serves it with nginx.
#
# NOT VERIFIED: Docker was unavailable where this was written. The build itself
# (`npm run build`) is verified -- see README.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --silent --no-fund --no-audit
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# The API is served by the backend; proxy to it so the browser uses one origin.
RUN printf '%s\n' \
  'server {' \
  '  listen 80;' \
  '  root /usr/share/nginx/html;' \
  '  location / { try_files $uri /index.html; }' \
  '  location ~ ^/(audit|audits|health|detectors) {' \
  '    proxy_pass http://backend:8000;' \
  '    proxy_set_header Host $host;' \
  '  }' \
  '}' > /etc/nginx/conf.d/default.conf
EXPOSE 80
