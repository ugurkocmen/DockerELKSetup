#!/bin/bash

# Renk kodları
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ELK Stack versiyonu
ELK_VERSION="7.17.10"

# Docker kontrolü
echo -e "${YELLOW}ELK Stack Kurulum Scripti${NC}"
echo "============================"

# Docker kontrolü
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker bulunamadı! Önce Docker'ı yüklemeniz gerekiyor.${NC}"
    echo "docker_kurulum.sh scriptini çalıştırarak Docker'ı kurabilirsiniz."
    exit 1
fi

# Elasticsearch için VM parametresi ayarı
echo -e "${GREEN}1. Elasticsearch için sistem parametreleri ayarlanıyor...${NC}"
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf > /dev/null
sudo sysctl -w vm.max_map_count=262144

# Dizin yapısını oluştur
echo -e "${GREEN}2. ELK Stack dizin yapısı oluşturuluyor...${NC}"
mkdir -p ~/elk-stack
cd ~/elk-stack

mkdir -p ./logstash/config ./logstash/pipeline ./kibana/config

# docker-compose.yml dosyası oluştur
echo -e "${GREEN}3. Docker Compose dosyası oluşturuluyor...${NC}"
cat > docker-compose.yml << EOL
version: '3.7'

services:
  # Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=elk-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - 9200:9200
      - 9300:9300
    networks:
      - elk-network

  # Logstash
  logstash:
    image: docker.elastic.co/logstash/logstash:${ELK_VERSION}
    container_name: logstash
    environment:
      - "LS_JAVA_OPTS=-Xmx256m -Xms256m"
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
      - ./logstash/pipeline/logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - 5000:5000
      - 5044:5044
      - 9600:9600
    networks:
      - elk-network
    depends_on:
      - elasticsearch

  # Kibana
  kibana:
    image: docker.elastic.co/kibana/kibana:${ELK_VERSION}
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=changeme
    volumes:
      - ./kibana/config/kibana.yml:/usr/share/kibana/config/kibana.yml
    ports:
      - 5601:5601
    networks:
      - elk-network
    depends_on:
      - elasticsearch

networks:
  elk-network:
    driver: bridge

volumes:
  elasticsearch-data:
    driver: local
EOL

# Logstash yapılandırma
echo -e "${GREEN}4. Logstash yapılandırması oluşturuluyor...${NC}"
cat > ./logstash/config/logstash.yml << EOL
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
xpack.monitoring.elasticsearch.username: elastic
xpack.monitoring.elasticsearch.password: changeme
EOL

# Logstash pipeline
echo -e "${GREEN}5. Logstash pipeline yapılandırması oluşturuluyor...${NC}"
cat > ./logstash/pipeline/logstash.conf << EOL
input {
  tcp {
    port => 5000
    codec => json
  }
  beats {
    port => 5044
  }
}

filter {
  # Filtreleri burada yapılandırabilirsiniz
  # Örnek: grok kullanarak logları ayrıştırma:
  # grok {
  #   match => { "message" => "%{COMBINEDAPACHELOG}" }
  # }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "changeme"
  }
  stdout {
    codec => rubydebug
  }
}
EOL

# Kibana yapılandırma
echo -e "${GREEN}6. Kibana yapılandırması oluşturuluyor...${NC}"
cat > ./kibana/config/kibana.yml << EOL
server.name: kibana
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://elasticsearch:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "changeme"
xpack.encryptedSavedObjects.encryptionKey: "supersecret32charactersencryptionkey"
EOL

# ELK Stack'i başlat
echo -e "${GREEN}7. ELK Stack başlatılıyor...${NC}"
sudo docker compose up -d

# Durum kontrolü
echo -e "${GREEN}8. Konteyner durumları kontrol ediliyor...${NC}"
sleep 10
sudo docker ps

echo -e "${YELLOW}ELK Stack Kurulumu Tamamlandı!${NC}"
echo -e "Elasticsearch: ${GREEN}http://localhost:9200${NC}"
echo -e "Kibana: ${GREEN}http://localhost:5601${NC}"
echo -e "Kullanıcı adı: ${GREEN}elastic${NC}"
echo -e "Şifre: ${GREEN}changeme${NC}"
echo ""
echo -e "${YELLOW}Önemli:${NC} Kibana'ya ilk erişim biraz zaman alabilir, Elasticsearch'ün tam olarak başlaması beklenmelidir."
echo "Tüm servislerin sağlıklı çalıştığından emin olmak için şu komutu kullanabilirsiniz:"
echo "sudo docker compose ps" 