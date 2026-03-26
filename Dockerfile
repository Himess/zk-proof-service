FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY src/ ./src/
COPY circuits/ ./circuits/
COPY favicon.png ./favicon.png

ENV PORT=7860
EXPOSE 7860

CMD ["npx", "tsx", "src/server.ts"]
