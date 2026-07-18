#!/bin/bash
set -e

apt-get update && apt-get upgrade -y

apt-get install -y \
  curl git ca-certificates gnupg lsb-release ufw fail2ban

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

useradd -m -s /bin/bash deploy
usermod -aG docker deploy

mkdir -p /home/deploy/.ssh
echo "$DEPLOY_PUBLIC_KEY" >> /home/deploy/.ssh/authorized_keys
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh

mkdir -p /opt/argus
chown deploy:deploy /opt/argus

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

systemctl enable fail2ban
systemctl start fail2ban

echo "deploy ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/bin/docker compose" >> /etc/sudoers.d/deploy

su - deploy -c "
  cd /opt/argus
  git clone https://github.com/argus-scan/infra.git infra
  cd infra
  cp .env.example .env
"

echo "Server ready. Edit /opt/argus/infra/.env then run: cd /opt/argus/infra && docker compose up -d"
