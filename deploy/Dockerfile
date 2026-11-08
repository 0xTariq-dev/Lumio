FROM node:24-bookworm-slim AS build

WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@10.26.1 --activate

COPY . .
RUN pnpm install --frozen-lockfile

ARG BASE_PATH=/
ARG PORT=21831
ENV BASE_PATH=${BASE_PATH} \
    PORT=${PORT}

RUN pnpm --filter @workspace/api-server run build \
    && pnpm --filter @workspace/veridict run build

FROM node:24-bookworm-slim AS api

WORKDIR /workspace
ENV NODE_ENV=production \
    PORT=8080

COPY --from=build --chown=node:node /workspace/package.json ./package.json
COPY --from=build --chown=node:node /workspace/node_modules ./node_modules
COPY --from=build --chown=node:node /workspace/artifacts/api-server/package.json ./artifacts/api-server/package.json
COPY --from=build --chown=node:node /workspace/artifacts/api-server/node_modules ./artifacts/api-server/node_modules
COPY --from=build --chown=node:node /workspace/artifacts/api-server/dist ./artifacts/api-server/dist

USER node
EXPOSE 8080
CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]

FROM nginx:stable-alpine AS web

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/artifacts/veridict/dist/public /usr/share/nginx/html

EXPOSE 8080
