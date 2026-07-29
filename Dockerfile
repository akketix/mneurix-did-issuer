# mneurix-did-issuer — multi-stage image (mirrors mneurix-lattice's hardened Dockerfile).
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
COPY packages/*/package.json ./packages/*/.
COPY services/*/package.json ./services/*/.
RUN npm ci --workspaces --include-workspace-root
COPY tsconfig*.json ./
COPY packages ./packages
COPY services ./services
RUN npm run build

FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
RUN npm prune --omit=dev --workspaces --include-workspace-root \
	&& chown -R node:node /app
USER node
EXPOSE 7004
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
	CMD node -e "fetch('http://localhost:'+(process.env.DID_ISSUER_PORT||7004)+'/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/services/did-issuer/src/index.js"]
