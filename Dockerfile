FROM node:22-slim

# Install GitHub CLI, SSH client, and Tailscale deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssh-client \
    ca-certificates \
    iptables \
    iproute2 \
    netcat-openbsd \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build && chmod +x start.sh

ENV PORT=3000
EXPOSE 3000
CMD ["./start.sh"]

