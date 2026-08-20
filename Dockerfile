FROM node:22-alpine
EXPOSE 3000

WORKDIR /app
COPY . /app
COPY config.env.js config.js
RUN npm i -g pnpm && \
  apk add --update --no-cache \
  python3 gcc make g++ zlib-dev \
  libtool autoconf automake && \
  pnpm install --frozen-lockfile && pnpm build && \
  pnpm prune --prod && \
  rm -rf src

CMD pnpm start