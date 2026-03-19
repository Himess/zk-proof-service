FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY src/ ./src/
COPY circuits/ ./circuits/

ENV PORT=3402
EXPOSE 3402

CMD ["npx", "tsx", "src/server.ts"]
