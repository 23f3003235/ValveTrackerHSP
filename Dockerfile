FROM node:22-alpine
WORKDIR /app
COPY server.js package.json ./
COPY public ./public
ENV DATA_DIR=/data PORT=3000 NODE_NO_WARNINGS=1
VOLUME /data
EXPOSE 3000
USER node
CMD ["node", "server.js"]
