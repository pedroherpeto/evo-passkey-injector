FROM node:20-alpine

WORKDIR /app

# Instala apenas deps de producao. package.json copiado primeiro p/ cache de layer.
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

COPY index.js ./
COPY public ./public

ENV PORT=8080
EXPOSE 8080

USER node
CMD ["node", "index.js"]
