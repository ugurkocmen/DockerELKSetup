#!/bin/bash

# ELK Stack Otomatik Kurulum Scripti
# Bu script Docker, Docker Compose ve ELK Stack'i otomatik olarak kurar
# /opt/elk-stack dizinine kurulum yapar

# Renkli çıktı fonksiyonları
function print_info() {
    echo -e "\e[1;34m[BİLGİ]\e[0m $1"
}

function print_success() {
    echo -e "\e[1;32m[BAŞARILI]\e[0m $1"
}

function print_error() {
    echo -e "\e[1;31m[HATA]\e[0m $1"
}

function print_warning() {
    echo -e "\e[1;33m[UYARI]\e[0m $1"
}

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    print_error "Bu script root yetkisi gerektirir, lütfen 'sudo' ile çalıştırın."
    exit 1
fi

print_info "ELK Stack otomatik kurulumu başlatılıyor..."

# Sistem güncellemesi
print_info "Sistem güncelleniyor..."
apt update
apt upgrade -y

# Eski Docker sürümlerini kaldırma
print_info "Eski Docker sürümleri kaldırılıyor (varsa)..."
apt remove -y docker docker-engine docker.io containerd runc

# Docker için gerekli paketleri kurma
print_info "Docker için gerekli paketler kuruluyor..."
apt install -y apt-transport-https ca-certificates curl software-properties-common gnupg lsb-release

# Docker GPG anahtarı ekleme
print_info "Docker GPG anahtarı ekleniyor..."
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Docker deposu ekleme
print_info "Docker deposu ekleniyor..."
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Sistem güncellemesi
print_info "Paket listesi güncelleniyor..."
apt update

# Docker kurulumu
print_info "Docker kuruluyor..."
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Docker'ı başlatma ve etkinleştirme
print_info "Docker servisi başlatılıyor ve etkinleştiriliyor..."
systemctl start docker
systemctl enable docker

# Docker Compose kurulumu
print_info "Docker Compose kuruluyor..."
curl -L "https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# ELK Stack için dizin yapısı oluşturma
print_info "ELK Stack için dizin yapısı oluşturuluyor..."
mkdir -p /opt/elk-stack/{elasticsearch/data,logstash/config,logstash/pipeline,kibana/config}

# Docker-compose.yml dosyasını oluşturma
print_info "Docker-compose.yml dosyası oluşturuluyor..."
cat > /opt/elk-stack/docker-compose.yml << 'EOL'
version: '3.7'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.1
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=es-docker-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
      - network.host=0.0.0.0
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - ./elasticsearch/data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - elk

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.1
    container_name: logstash
    environment:
      - LS_JAVA_OPTS=-Xmx256m -Xms256m
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "5044:5044"
      - "5045:5045"
      - "5140:5140/udp"
      - "9600:9600"
    networks:
      - elk
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.1
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - server.host=0.0.0.0
    ports:
      - "5601:5601"
    networks:
      - elk
    depends_on:
      - elasticsearch

networks:
  elk:
    driver: bridge
EOL

# Logstash konfigürasyonu oluşturma
print_info "Logstash konfigürasyonu oluşturuluyor..."
cat > /opt/elk-stack/logstash/config/logstash.yml << 'EOL'
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: [ "http://elasticsearch:9200" ]
EOL

# Logstash pipeline konfigürasyonu oluşturma
print_info "Logstash pipeline konfigürasyonu oluşturuluyor..."
cat > /opt/elk-stack/logstash/pipeline/main.conf << 'EOL'
input {
  # Suricata logları için
  beats {
    port => 5044
    tags => ["suricata"]
    type => "suricata"
  }
  
  # pfSense logları için
  syslog {
    port => 5140
    type => "pfsense"
    tags => ["pfsense"]
  }
  
  # Windows logları için Beats input
  beats {
    port => 5045
    type => "windows"
    tags => ["windows"]
  }
}

filter {
  if [type] == "suricata" {
    mutate {
      add_field => { "source_type" => "suricata" }
    }
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
  
  if [type] == "pfsense" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      target => "@timestamp"
    }
    mutate {
      add_field => { "source_type" => "pfsense" }
    }
  }

  if [type] == "windows" {
    mutate {
      add_field => { "source_type" => "windows" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "%{source_type}-%{+YYYY.MM.dd}"
  }
}
EOL

# Virtual memory ayarları (Elasticsearch için)
print_info "Virtual memory ayarları yapılıyor..."
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# Firewall kuralları (eğer ufw kurulu ise)
if command -v ufw &> /dev/null; then
    print_info "Firewall kuralları ayarlanıyor..."
    ufw allow 5601/tcp  # Kibana
    ufw allow 9200/tcp  # Elasticsearch
    ufw allow 5044/tcp  # Logstash Beats (Suricata)
    ufw allow 5045/tcp  # Logstash Beats (Windows)
    ufw allow 5140/udp  # Logstash Syslog (pfSense)
fi

# ELK Stack'i başlatma
print_info "ELK Stack başlatılıyor..."
cd /opt/elk-stack
docker-compose up -d

# Kurulumun tamamlandığını kontrol etme
sleep 20
if docker ps | grep -q "elasticsearch" && docker ps | grep -q "logstash" && docker ps | grep -q "kibana"; then
    print_success "ELK Stack kurulumu başarıyla tamamlandı!"
    
    # IP adresini alma
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    
    print_info "Kibana arayüzüne erişmek için: http://$IP_ADDRESS:5601"
    print_info "Elasticsearch API'sine erişmek için: http://$IP_ADDRESS:9200"
    print_info "Logstash Beats portları (Suricata): $IP_ADDRESS:5044"
    print_info "Logstash Beats portları (Windows): $IP_ADDRESS:5045"
    print_info "Logstash Syslog portu (pfSense): $IP_ADDRESS:5140/udp"
    
    # Suricata için Filebeat konfigürasyonu
    print_info "Suricata için örnek Filebeat konfigürasyonu:"
    echo "---------------------------------------------------"
    echo "filebeat.modules:"
    echo "  - module: suricata"
    echo "    eve:"
    echo "      enabled: true"
    echo "      var.paths: [\"/var/log/suricata/eve.json\"]"
    echo ""
    echo "output.logstash:"
    echo "  hosts: [\"$IP_ADDRESS:5044\"]"
    echo "---------------------------------------------------"
    
    # Windows için Winlogbeat konfigürasyonu
    print_info "Windows için örnek Winlogbeat konfigürasyonu:"
    echo "---------------------------------------------------"
    echo "winlogbeat.event_logs:"
    echo "  - name: Application"
    echo "    ignore_older: 72h"
    echo "  - name: System"
    echo "  - name: Security"
    echo "  - name: Microsoft-Windows-Sysmon/Operational"
    echo ""
    echo "output.logstash:"
    echo "  hosts: [\"$IP_ADDRESS:5045\"]"
    echo "---------------------------------------------------"
    
    # pfSense için Syslog konfigürasyonu
    print_info "pfSense için Syslog konfigürasyonu:"
    echo "---------------------------------------------------"
    echo "Status > System Logs > Settings"
    echo "Enable Remote Logging: Checked"
    echo "Server 1: $IP_ADDRESS"
    echo "Port: 5140"
    echo "Protocol: UDP"
    echo "---------------------------------------------------"
    
else
    print_error "ELK Stack kurulumunda bir sorun oluştu. Docker container durumlarını kontrol edin."
    docker ps
fi

print_info "Kurulum tamamlandı!"
