# Docker ile ELK Stack Kurulum ve Yapılandırma Kılavuzu

## İçindekiler
1. Docker Kurulumu
2. ELK Stack Kurulumu
3. Karşılaşılan Hatalar ve Çözümleri
4. Kibana Yapılandırması
5. Güvenlik Ayarları
6. SIEM ve SOC İşlemleri
7. En İyi Uygulamalar

## 1. Docker Kurulumu

### Gerekli Paketlerin Yüklenmesi
```bash
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
```

### Docker GPG Anahtarını Sisteme Ekleme
```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
```

### Docker Repository'sini Sisteme Ekleme
```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### Docker Kurulumu
```bash
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
```

### Docker'ın Çalıştığını Doğrulama
```bash
sudo docker run hello-world
```

### Docker Kullanıcı İzinleri (Opsiyonel)
```bash
sudo usermod -aG docker $USER
```
Not: Bu komutu çalıştırdıktan sonra, değişikliklerin etkili olması için yeniden oturum açmanız gerekebilir.

## 2. ELK Stack Kurulumu

### Proje Dizinini Oluşturma
```bash
mkdir -p ~/elk-stack && cd ~/elk-stack
```

### Elasticsearch, Logstash ve Kibana için Docker Compose Dosyası

```bash
mkdir -p ./logstash/config ./logstash/pipeline ./kibana/config
```

Aşağıdaki içeriği ~/elk-stack/docker-compose.yml dosyasına kaydedin:

```yaml
version: '3.7'

services:
  # Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.10
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
    image: docker.elastic.co/logstash/logstash:7.17.10
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
    image: docker.elastic.co/kibana/kibana:7.17.10
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
```

### Logstash Yapılandırması

1. Logstash Config Dosyası (~/elk-stack/logstash/config/logstash.yml):
```yaml
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
xpack.monitoring.elasticsearch.username: elastic
xpack.monitoring.elasticsearch.password: changeme
```

2. Logstash Pipeline Dosyası (~/elk-stack/logstash/pipeline/logstash.conf):
```conf
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
  # Configure your filters here based on your log formats
  # Example: Using grok to parse logs
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
```

### Kibana Yapılandırması

Kibana Config Dosyası (~/elk-stack/kibana/config/kibana.yml):
```yaml
server.name: kibana
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://elasticsearch:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "changeme"
xpack.encryptedSavedObjects.encryptionKey: "supersecret32charactersencryptionkey"
```

### Elasticsearch için Sistem Parametrelerini Yapılandırma

Elasticsearch için maksimum map sayısı (vm.max_map_count) parametresini ayarlama:
```bash
sudo sysctl -w vm.max_map_count=262144
```

Bu ayarı kalıcı yapmak için:
```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```

### ELK Stack'i Başlatma

```bash
sudo docker compose up -d
```

### Servislerin Durumunu Kontrol Etme

```bash
sudo docker ps
```

## 3. Karşılaşılan Hatalar ve Çözümleri

### Hata 1: Logstash Mount Sorunu

**Hata Mesajı:**
```
Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error mounting "/home/cryptic/elk-stack/logstash/config/logstash.yml" to rootfs at "/usr/share/logstash/config/logstash.yml": create mountpoint for /usr/share/logstash/config/logstash.yml mount: cannot create subdirectories in "/var/lib/docker/overlay2/1961d529553b61dace453c2e790c06f310e925acc420372cde4664047fe4c251/merged/usr/share/logstash/config/logstash.yml": not a directory: unknown: Are you trying to mount a directory onto a file (or vice-versa)? Check if the specified host path exists and is the expected type
```

**Çözüm:**
Problem, logstash.yml bir dosya olması gerekirken dizin olarak oluşturulmuştu. Sorunu çözmek için şu adımları takip ettik:

```bash
# Yanlış oluşturulan dizini kaldırma
sudo rm -rf logstash/config/logstash.yml

# Dosyayı doğru şekilde oluşturma
echo 'http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]' > logstash/config/logstash.yml

# Dizin bağlantılarını değiştirme (docker-compose.yml'da)
# - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
# Yerine:
# - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
```

### Hata 2: Logstash Java Options Sorunu

**Hata Mesajı:**
```
Error: Could not find or load main class "-Xmx256m
Caused by: java.lang.ClassNotFoundException: "-Xmx256m
```

**Çözüm:**
docker-compose.yml dosyasında LS_JAVA_OPTS çevre değişkeni formatı yanlıştı.

```yaml
# Hatalı format:
environment:
  - LS_JAVA_OPTS="-Xmx256m -Xms256m"

# Doğru format:
environment:
  - "LS_JAVA_OPTS=-Xmx256m -Xms256m"
```

### Hata 3: Kibana API Integration Key Hatası

**Hata Mesajı:**
```
A new encryption key is generated for saved objects each time you start Kibana. Without a persistent key, you cannot delete or modify rules after Kibana restarts. To set a persistent key, add the xpack.encryptedSavedObjects.encryptionKey setting with any text value of 32 or more characters to the kibana.yml file.
```

**Çözüm:**
Kibana için kalıcı bir şifreleme anahtarı oluşturmamız gerekiyordu. kibana.yml dosyasına aşağıdaki satırı ekledik:

```yaml
xpack.encryptedSavedObjects.encryptionKey: "supersecret32charactersencryptionkey"
```

Ve docker-compose.yml dosyasını güncelleyerek Kibana'nın bu yapılandırma dosyasını kullanmasını sağladık:

```yaml
volumes:
  - ./kibana/config/kibana.yml:/usr/share/kibana/config/kibana.yml
```

## 4. Kibana Yapılandırması

### Kibana'ya Erişim

Tarayıcıda http://localhost:5601 adresine giderek Kibana arayüzüne erişebilirsiniz.

**Kimlik Bilgileri:**
- Kullanıcı Adı: elastic
- Şifre: changeme

### Örnek Dashboard Oluşturma

1. Kibana arayüzünde sol tarafta bulunan menüden "Dashboard" seçeneğine tıklayın.
2. "Create dashboard" düğmesine tıklayın.
3. "Create visualization" düğmesine tıklayıp istediğiniz grafiği seçin.
4. Veri kaynağı ve grafik özellikleri yapılandırın.
5. Dashboardu kaydedin.

### Örnek Güvenlik Dashboard Elemanları:

- Başarısız oturum açma denemeleri grafiği
- Şüpheli IP aktiviteleri tablosu
- Coğrafi konum haritası
- En aktif kullanıcılar listesi
- Ağ trafiği özeti

## 5. Güvenlik Ayarları

### X-Pack Güvenlik

ELK Stack'te güvenliği etkinleştirmek için Elasticsearch'te xpack.security.enabled=true parametresini ayarladık. Bununla birlikte:

1. Elasticsearch için varsayılan admin kullanıcısı ve şifresi belirledik:
```yaml
ELASTIC_PASSWORD=changeme
```

2. Kibana'nın Elasticsearch'e kimlik doğrulama ile bağlanmasını sağladık:
```yaml
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
```

3. Logstash'in Elasticsearch'e kimlik doğrulama ile bağlanmasını sağladık:
```conf
user => "elastic"
password => "changeme"
```

4. Kibana'da kaydedilen nesneler için kalıcı şifreleme anahtarı ekledik:
```yaml
xpack.encryptedSavedObjects.encryptionKey: "supersecret32charactersencryptionkey"
```

### Daha Güvenli Bir ELK Stack İçin Öneriler

1. **Güçlü şifreler kullanın:**
   - Üretim ortamlarında "changeme" gibi varsayılan şifreleri değiştirin
   - En az 12 karakter uzunluğunda karmaşık şifreler kullanın

2. **TLS/SSL yapılandırması ekleyin:**
   ```yaml
   # Elasticsearch
   xpack.security.transport.ssl.enabled: true
   xpack.security.transport.ssl.verification_mode: certificate
   xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
   xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
   ```

3. **Ağ güvenliği sağlayın:**
   - ELK Stack'i iç ağda tutun
   - Gerekirse reverse proxy ile HTTPS ve erişim kontrolü ekleyin

4. **Rol tabanlı erişim kontrolü yapılandırın:**
   - Elasticsearch ve Kibana'da farklı roller oluşturun (admin, analyst, readonly)
   - Kullanıcıların yalnızca ihtiyaç duydukları indekslere erişmesini sağlayın

## 6. SIEM ve SOC İşlemleri

### Kural ve Korelasyon Süreçleri

#### Temel Kural Oluşturma

1. Kibana'da Security > Rules > Create New Rule
2. İlgili kural tipini seçin (Threshold, New Value, EQL, etc.)
3. Örnek bir kural:
```
process where process.name == "powershell.exe" and 
process.args_count > 5 and event.type == "start"
```

#### Korelasyon Mantığı Örneği

Başarısız oturum açma ardından başarılı oturum açma ve yetki yükseltme:

1. İlgili loglar arasında zamansal ilişki kurun (zaman aralığı: 10 dakika)
2. Olayları kullanıcı veya IP adresine göre gruplayın
3. Risk skorlaması yapılandırın (örn: 75/100)

### Timeline Analizi

Timeline oluşturma ve kullanma:

1. Security > Timelines > Create new timeline
2. "Add to timeline" ile olayları ekleyin
3. Filtreler uygulayın (IP, kullanıcı, zaman aralığı)
4. Timeline üzerine notlar ekleyin
5. Bulgularınızı belgelendirin

Örnek Timeline Çalışması:
```
1. Tespit: 10:15'te brute force login denemeleri
2. 10:20'de başarılı oturum açma
3. 10:25'te bir PowerShell komutu ile şüpheli dosya indirilmesi
4. 10:30'da güvenlik hizmetlerinin devre dışı bırakılması
```

### Dashboard Oluşturma

Güvenlik odaklı dashboard örneği:

1. Login aktiviteleri paneli
   - Zaman grafikleri
   - IP ve kullanıcılara göre gruplandırma

2. Ağ aktivite paneli
   - En çok trafik üreten sistemler
   - Anormal port kullanımları

3. Endpoint aktivite paneli
   - PowerShell/Cmd kullanımları
   - Yeni yüklenen uygulamalar

4. Alarm özeti paneli
   - Severity'e göre gruplandırılmış alarmlar
   - Çözülmemiş alarmlar sayısı

## 7. En İyi Uygulamalar

### Docker ve ELK Yapılandırması

1. **Docker Compose En İyi Uygulamaları**
   - Servis bağımlılıklarını doğru yapılandırın (depends_on)
   - Konteynerleri isimlendirin (container_name)
   - Kalıcı veri için named volume kullanın

2. **Elasticsearch Performans İyileştirmeleri**
   - JVM heap size'ı fiziksel RAM'in %50'sinden fazla olmamalı
   - vm.max_map_count en az 262144 olarak ayarlanmalı
   - Üretim ortamlarında multinode cluster kullanın

3. **Logstash Optimizasyonu**
   - Pipeline işleme performansını iyileştirmek için worker sayısını ayarlayın
   - Grok pattern'ları optimize edin
   - Buffer ayarlarını trafik hacmine göre ayarlayın

4. **Kibana Dashboard Performansı**
   - Karmaşık sorgulardan kaçının
   - Zaman aralığını sınırlayın
   - Aynı panoda çok fazla görselleştirme kullanmayın

### Log Yönetimi

1. **Etkili Log Toplama Stratejisi**
   - Hangi logların kritik olduğunu belirleyin
   - Düzenli rotasyon ve arşivleme politikası oluşturun
   - Log formatlarını standartlaştırın

2. **İndeks Stratejisi**
   - Log tipine göre indeks oluşturun
   - İndeks rotasyon politikası belirleyin (günlük, haftalık)
   - İndeks yaşam döngüsünü yönetin (sıcak/ılık/soğuk katmanlar)

### SIEM İşlemleri

1. **Kural Geliştirme İpuçları**
   - Başlangıçta düşük hassasiyetle başlayıp zamanla ayarlayın
   - False positive azaltmak için whitelist kullanın
   - Kuralları düzenli olarak gözden geçirin

2. **Olay Yanıt İş Akışı**
   - Standart bir olay yanıt prosedürü oluşturun
   - Alarm triyaj süreci tanımlayın
   - Bulguları ve çözümleri belgelendirin

3. **Tehdit Avcılığı Teknikleri**
   - Bilinen IoC'leri (Indicators of Compromise) arayın
   - Baseline davranış profillerini oluşturun
   - MITRE ATT&CK framework'ünü referans alın

### Örnek Senaryolar

**Senaryo 1: Brute Force Tespit ve Yanıt**

1. Kural Yapılandırması:
```
threshold: 5 failed login attempts in 2 minutes for same user
```

2. Alarma yanıt:
   - Başarısız ve başarılı oturum açma girişimlerini Timeline'a ekle
   - Kaynak IP adresini analiz et ve coğrafi konumu belirle
   - İlgili kullanıcının normal davranış profilini kontrol et

3. Yanıt eylemleri:
   - Şüpheli IP adresini geçici olarak engelle
   - Kullanıcıya parola sıfırlama uygula
   - Tüm kullanıcı oturumlarını sonlandır

**Senaryo 2: Şüpheli PowerShell Aktivitesi**

1. Kural Yapılandırması:
```
process where process.name == "powershell.exe" and 
process.command_line : ("*DownloadString*" or "*Invoke-Expression*") and 
event.type == "start"
```

2. Alarma yanıt:
   - Tam PowerShell komutunu analiz et
   - PowerShell işleminin üst ve alt süreçlerini kontrol et
   - İndirilen dosya veya çalıştırılan komutları incele

3. Yanıt eylemleri:
   - Sistemi izole et
   - Bellek ve disk adli analiz gerçekleştir
   - IOC'leri diğer sistemlerde ara

Bu kapsamlı dokümantasyon, Docker ile ELK Stack kurulumundan, güvenlik ayarlarına, SIEM işlemlerine ve en iyi uygulamalara kadar tüm süreci kapsamaktadır. Karşılaşılan hatalar ve çözümleri de içererek, gerçek bir üretim ortamında ELK Stack'in nasıl kurulup yapılandırılacağına dair pratik bir rehber sunmaktadır. 