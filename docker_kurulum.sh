#!/bin/bash

# Renk kodları
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Docker Kurulum Scripti${NC}"
echo "============================"

# Root yetkileri kontrolü
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Bu script root yetkileri gerektiriyor.${NC}"
  echo "Lütfen sudo ile çalıştırın: sudo ./docker_kurulum.sh"
  exit 1
fi

echo -e "${GREEN}1. Sistem paketleri güncelleniyor...${NC}"
apt-get update

echo -e "${GREEN}2. Gerekli paketler yükleniyor...${NC}"
apt-get install -y apt-transport-https ca-certificates curl software-properties-common

echo -e "${GREEN}3. Docker GPG anahtarı indiriliyor...${NC}"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo -e "${GREEN}4. Docker repository sisteme ekleniyor...${NC}"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

echo -e "${GREEN}5. Paket listesi güncelleniyor...${NC}"
apt-get update

echo -e "${GREEN}6. Docker yükleniyor...${NC}"
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo -e "${GREEN}7. Docker servisinin durumu kontrol ediliyor...${NC}"
systemctl status docker --no-pager

echo -e "${GREEN}8. Docker Compose eklentisinin durumu kontrol ediliyor...${NC}"
docker compose version

echo -e "${GREEN}9. Elasticsearch için sistem limitleri ayarlanıyor...${NC}"
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
sysctl -p

# Mevcut kullanıcıyı docker grubuna ekle
echo -e "${GREEN}10. Mevcut kullanıcıyı docker grubuna ekleniyor...${NC}"
usermod -aG docker $SUDO_USER

echo -e "${YELLOW}Kurulum tamamlandı!${NC}"
echo "Docker'ı sudo olmadan kullanabilmek için oturumu kapatıp yeniden açın veya:"
echo "su - $SUDO_USER"
echo "komutu ile yeni bir shell açın."
echo -e "${YELLOW}Test etmek için:${NC} docker run hello-world" 