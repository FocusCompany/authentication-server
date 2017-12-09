FROM node:9

## ~= cd /app
WORKDIR /app

## When running `docker build`, this moves the files from
## the passed context to /app
COPY src/ package-lock.json package.json ./

RUN npm install --production

CMD ["npm", "start", "run"]