FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache python3 py3-pip git docker-cli curl wget tar \
  && python3 -m venv /opt/secureflow-venv \
  && /opt/secureflow-venv/bin/pip install --no-cache-dir semgrep pip-audit \
  && wget -O /tmp/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
  && chmod +x /usr/local/bin/gitleaks \
  && rm -f /tmp/gitleaks.tar.gz \
  && wget -O /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz \
  && tar -xzf /tmp/trivy.tar.gz -C /tmp \
  && mv /tmp/trivy /usr/local/bin/trivy \
  && chmod +x /usr/local/bin/trivy \
  && rm -f /tmp/trivy.tar.gz \
  && mkdir -p /app/workspace/repos

ENV PATH="/opt/secureflow-venv/bin:${PATH}"

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 5050

CMD ["npm", "start"]
