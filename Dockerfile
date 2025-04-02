FROM node:18-slim

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

RUN npm install

# Bundle app source
COPY . .

# Create necessary directories
RUN mkdir -p data uploads/temp

# Set environment variables
ENV PORT=3000
ENV NODE_ENV=production

# Expose the port the app runs on
EXPOSE 3000

# Command to run the application
CMD ["node", "app.js"]