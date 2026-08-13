# QLint frontend image.
#
# The frontend is a Vite build with no server-side component: the output is
# static files. So the image that ships is nginx serving a directory, not Node
# serving a dev server -- smaller, faster, and it does not carry a build
# toolchain into production.

# ---------------------------------------------------------------- stage 1 ---
# Node 20 LTS, matching the version this project is developed against.
FROM node:20-alpine AS builder

WORKDIR /app

# Lockfile-driven install in its own layer so it is cached across source edits.
# `npm ci` rather than `npm install`: it installs exactly what
# package-lock.json pins and fails if the two disagree, which is what a
# reproducible image wants.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---------------------------------------------------------------- stage 2 ---
FROM nginx:alpine AS runtime

# Just the build output. No node_modules, no source, no Node runtime.
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
