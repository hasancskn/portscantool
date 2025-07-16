# 🚀 Advanced IP-Port Scanner - Gelişmiş IP-Port Tarama Sistemi

Güvenli ve kapsamlı port tarama sistemi. Nmap tabanlı gelişmiş tarama, zamanlanmış görevler, anomali tespiti ve alarm sistemi ile birlikte gelir.

## ✨ Özellikler

### 🔍 Gelişmiş Tarama
- **Nmap Entegrasyonu**: `nmap -sV -O` komutları ile detaylı tarama
- **Servis Versiyon Tespiti**: Açık portlardaki servislerin versiyon bilgileri
- **İşletim Sistemi Tespiti**: Hedef sistemin OS bilgileri
- **MAC Adresi ve Vendor**: Cihaz bilgileri
- **Banner Grabbing**: Servis banner'ları

### 📊 Veritabanı ve Raporlama
- **PostgreSQL Veritabanı**: Tüm tarama sonuçları saklanır
- **Audit Logging**: Tüm işlemler kayıt altına alınır
- **Excel Export**: Sonuçları Excel formatında indirme
- **Dashboard**: Gerçek zamanlı istatistikler ve grafikler

### ⏰ Zamanlanmış Tarama
- **Otomatik Tarama**: Belirli aralıklarla otomatik tarama
- **Çoklu Hedef**: Birden fazla IP/host için toplu tarama
- **Esnek Zamanlama**: Saniye, dakika, saat bazında ayarlama

### 🚨 Anomali Tespiti ve Alarm
- **Değişiklik Tespiti**: Yeni açılan/kapanan portlar
- **Servis Değişiklikleri**: Servis versiyon değişiklikleri
- **Email Alarmları**: SMTP ile email bildirimleri
- **Webhook Alarmları**: Slack, Discord vb. entegrasyonlar
- **Severity Levels**: Kritik, yüksek, orta, düşük önem seviyeleri

### 🌐 Web Arayüzü
- **Modern UI**: Bootstrap 5 ile responsive tasarım
- **Gerçek Zamanlı**: Canlı güncellenen dashboard
- **Grafik Raporlar**: Plotly ile interaktif grafikler
- **Tablo Görünümleri**: Detaylı sonuç tabloları

## 🛠️ Teknoloji Stack

- **Backend**: Python 3.11, Flask
- **Veritabanı**: PostgreSQL 15
- **Tarama Motoru**: Nmap + python-nmap
- **Zamanlama**: schedule modülü
- **Frontend**: HTML5, Bootstrap 5, JavaScript, Plotly
- **Container**: Docker & Docker Compose
- **Alarm**: SMTP, Webhook (Slack/Discord)

## 📋 Gereksinimler

- Docker ve Docker Compose
- En az 2GB RAM
- İnternet bağlantısı (nmap güncellemeleri için)

## 🚀 Kurulum

### 1. Projeyi İndirin
```bash
git clone <repository-url>
cd advanced-port-scanner
```

### 2. Environment Ayarları
``config.py` dosyası oluşturun (opsiyonel):
```env
# Database Configuration
DATABASE_URL=postgresql://postgres:password@postgres:5432/port_scanner_db

# Flask Configuration
FLASK_SECRET_KEY=your-secret-key-change-this-in-production
FLASK_ENV=development

# Email Configuration (for alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=admin@example.com

# Webhook Configuration (for alerts)
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Scan Configuration
DEFAULT_SCAN_TIMEOUT=300
DEFAULT_MAX_THREADS=100
SCHEDULED_SCAN_INTERVAL=3600

# Nmap Configuration
NMAP_TIMING_TEMPLATE=T4
NMAP_SCRIPT_ARGS=version-intensity=5
```

### 3. Docker ile Başlatın
```bash
# Container'ları build et ve başlat
docker-compose up -d

# Logları kontrol et
docker-compose logs -f
```

### 4. Erişim
- **Ana Uygulama**: http://localhost:5000
- **Dashboard**: http://localhost:5000/dashboard
- **PostgreSQL**: localhost:5432

## 📖 Kullanım

### Manuel Port Tarama
1. Ana sayfada "Port Tarama" sekmesine gidin
2. Hedef host/IP adresini girin
3. Port aralığını belirleyin
4. "Port Taramasını Başlat" butonuna tıklayın
5. Sonuçları tabloda görüntüleyin

### Ağ Tarama
1. "Ağ Tarama" sekmesine gidin
2. CIDR formatında ağ aralığı girin (örn: 192.168.1.0/24)
3. "Ağ Taramasını Başlat" butonuna tıklayın
4. Aktif IP'leri görüntüleyin

### Zamanlanmış Tarama
1. Dashboard'da "Zamanlanmış" sekmesine gidin
2. "Yeni Ekle" butonuna tıklayın
3. Tarama adı, hedef hostlar, port aralığı ve zamanlama ayarlayın
4. Kaydedin

### Alarm Yönetimi
1. Dashboard'da "Alarmlar" sekmesine gidin
2. Son alarmları görüntüleyin
3. "Test Alarmı" butonu ile alarm sistemini test edin

## 🔧 Konfigürasyon

### Email Alarmları
Gmail kullanıyorsanız:
1. Gmail'de "2 Adımlı Doğrulama" aktif edin
2. "Uygulama Şifreleri" oluşturun
3. ``config.py` dosyasında SMTP ayarlarını yapın

### Webhook Alarmları
Slack için:
1. Slack workspace'inizde webhook URL oluşturun
2. ``config.py` dosyasında `WEBHOOK_URL` ayarlayın

### Nmap Ayarları
- `NMAP_TIMING_TEMPLATE`: Tarama hızı (T1-T5)
- `NMAP_SCRIPT_ARGS`: Versiyon tespiti yoğunluğu

## 📊 Dashboard Özellikleri

### İstatistikler
- Toplam tarama sayısı
- Son 30 günde yapılan taramalar
- Toplam açık port sayısı
- Toplam alarm sayısı
- Aktif zamanlanmış taramalar

### Grafikler
- Günlük tarama aktivitesi
- Port servis dağılımı
- Alarm trendleri

### Tablolar
- Son taramalar
- Son alarmlar
- Zamanlanmış taramalar

## 🔒 Güvenlik

### Önemli Notlar
- Sadece kendi ağınızda veya izin verilen sistemlerde tarama yapın
- Üretim ortamında güçlü şifreler kullanın
- Firewall kurallarını kontrol edin
- Rate limiting uygulayın

### Güvenlik Önerileri
1. ``config.py` dosyasını güvenli tutun
2. Veritabanı şifrelerini değiştirin
3. SSL/TLS sertifikası ekleyin
4. Düzenli güvenlik güncellemeleri yapın

## 🐛 Sorun Giderme

### Yaygın Sorunlar

**Container başlamıyor:**
```bash
# Logları kontrol et
docker-compose logs

# Container'ları yeniden başlat
docker-compose down
docker-compose up -d
```

**Nmap çalışmıyor:**
```bash
# Container içinde nmap'i test et
docker exec -it port-scanner-app nmap --version
```

**Veritabanı bağlantı hatası:**
```bash
# PostgreSQL container'ını kontrol et
docker-compose ps postgres
```

**Email alarmları çalışmıyor:**
- SMTP ayarlarını kontrol edin
- Gmail için "Daha az güvenli uygulama erişimi" aktif edin
- Firewall ayarlarını kontrol edin

## 📈 Performans

### Optimizasyon Önerileri
- Büyük ağlar için paralel tarama kullanın
- Nmap timing template'ini ayarlayın
- Veritabanı indekslerini optimize edin
- Container kaynaklarını artırın

### Ölçeklendirme
- Çoklu container instance'ları
- Load balancer ekleme
- Redis cache entegrasyonu
- Mikroservis mimarisi

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.



## 🔄 Güncellemeler

### v2.0.0 (Güncel)
- Nmap entegrasyonu eklendi
- PostgreSQL veritabanı desteği
- Zamanlanmış tarama sistemi
- Anomali tespiti ve alarm sistemi
- Gelişmiş dashboard
- Email ve webhook alarmları

### v1.0.0
- Temel port tarama
- Flask web arayüzü
- Excel export
- Docker desteği

---

**⚠️ Uyarı**: Bu araç sadece eğitim ve güvenlik testleri için tasarlanmıştır. Kötü niyetli kullanımdan kullanıcı sorumludur. 
