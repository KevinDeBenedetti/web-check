# Dockerfile pour le client web React
FROM oven/bun:1.1-alpine AS builder

WORKDIR /app

# Copier les fichiers de dépendances
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

# Copier le code source
COPY . .

# Build de production
RUN bun run build

# Serveur de production avec Nginx
FROM nginx:alpine

# Copier les fichiers buildés
COPY --from=builder /app/dist /usr/share/nginx/html

# Configuration Nginx pour React Router et proxy API
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
