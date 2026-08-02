FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production && npm install googleapis@^137.0.0 --save
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]
