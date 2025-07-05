# 🔍 Port Tarama Aracı

Modern ve kullanıcı dostu web tabanlı port tarama aracı. Güvenli ve hızlı port tarama yapın, sonuçları Excel formatında indirin.

## ✨ Özellikler

- 🌐 **Web Tabanlı Arayüz**: Modern ve responsive tasarım
- ⚡ **Hızlı Tarama**: Multi-threading ile paralel port tarama
- 📊 **Detaylı Raporlama**: Açık portlar, servis bilgileri ve istatistikler
- 📈 **Excel Export**: Sonuçları Excel dosyası olarak indirme
- 🐳 **Docker Desteği**: Kolay kurulum ve dağıtım
- 🔒 **Güvenli**: Timeout ve thread limitleri ile güvenli tarama
- 📱 **Mobil Uyumlu**: Tüm cihazlardan erişilebilir

## 🚀 Hızlı Başlangıç

### Docker ile Kurulum (Önerilen)

1. **Projeyi klonlayın:**
```bash
git clone https://github.com/kullaniciadi/port-scanner.git
cd port-scanner
```

2. **Docker Compose ile çalıştırın:**
```bash
docker-compose up -d
```

3. **Tarayıcınızda açın:**
```
http://localhost:5000
```

### Manuel Kurulum

1. **Python 3.8+ yükleyin**

2. **Bağımlılıkları yükleyin:**
```bash
pip install -r requirements.txt
```

3. **Uygulamayı çalıştırın:**
```bash
python app.py
```

4. **Tarayıcınızda açın:**
```
http://localhost:5000
```

## 📖 Kullanım

### Temel Kullanım

1. **Hedef Host/IP girin:**
   - IP adresi: `192.168.1.1`
   - Domain adı: `example.com`

2. **Port aralığını belirleyin:**
   - Başlangıç portu: `1`
   - Bitiş portu: `1024` (varsayılan)

3. **Tarama parametrelerini ayarlayın:**
   - **Timeout**: Port bağlantı zaman aşımı (varsayılan: 1 saniye)
   - **Maksimum Thread**: Eşzamanlı tarama sayısı (varsayılan: 100)

4. **"Taramayı Başlat" butonuna tıklayın**

### Gelişmiş Kullanım

#### Yaygın Port Aralıkları

| Amaç | Başlangıç | Bitiş | Açıklama |
|------|-----------|-------|----------|
| Hızlı Tarama | 1 | 1024 | Standart portlar |
| Web Servisleri | 80 | 443 | HTTP/HTTPS |
| Veritabanları | 1433 | 5432 | MSSQL, MySQL, PostgreSQL |
| Tam Tarama | 1 | 65535 | Tüm portlar (uzun sürer) |

#### Örnek Kullanım Senaryoları

**1. Web Sunucusu Tarama:**
```
Hedef: example.com
Port Aralığı: 80-443
Timeout: 2 saniye
```

**2. Veritabanı Sunucusu Tarama:**
```
Hedef: 192.168.1.100
Port Aralığı: 1433-5432
Timeout: 1 saniye
```

**3. Hızlı Güvenlik Kontrolü:**
```
Hedef: localhost
Port Aralığı: 1-1024
Timeout: 0.5 saniye
Thread: 200
```

## 📊 Sonuçlar ve Raporlama

### Ekran Çıktısı

Tarama sonuçları şu bilgileri içerir:

- **İstatistikler**: Toplam port, taranan port, açık port sayısı
- **Tarama Süresi**: İşlem tamamlanma süresi
- **Port Listesi**: Açık portlar, servis adları ve durumları

### Excel Raporu

Excel dosyası şu sütunları içerir:

| Sütun | Açıklama |
|-------|----------|
| Hedef Host | Taranan IP/domain |
| Tarama Zamanı | Tarama başlangıç tarihi/saati |
| Port | Port numarası |
| Servis | Port üzerinde çalışan servis |
| Durum | Port durumu (Open/Closed) |

## 🔧 Konfigürasyon

### Environment Variables

```bash
# Flask konfigürasyonu
FLASK_ENV=production
FLASK_DEBUG=false

# Port tarama ayarları
DEFAULT_TIMEOUT=1
DEFAULT_MAX_THREADS=100
```

### Docker Compose Özelleştirme

```yaml
version: '3.8'
services:
  port-scanner:
    build: .
    ports:
      - "8080:5000"  # Farklı port kullanımı
    environment:
      - FLASK_ENV=production
      - DEFAULT_TIMEOUT=2
    volumes:
      - ./logs:/app/logs
      - ./exports:/app/exports  # Excel dosyaları için
```

## 🛠️ Geliştirme

### Proje Yapısı

```
port-scanner/
├── app.py                 # Ana Flask uygulaması
├── requirements.txt       # Python bağımlılıkları
├── Dockerfile            # Docker imaj tanımı
├── docker-compose.yml    # Docker Compose konfigürasyonu
├── templates/
│   └── index.html        # Web arayüzü
├── logs/                 # Log dosyaları
└── README.md            # Bu dosya
```

### Yeni Özellik Ekleme

1. **Backend (Python):**
   - `app.py` dosyasına yeni endpoint ekleyin
   - Port tarama mantığını genişletin

2. **Frontend (HTML/JS):**
   - `templates/index.html` dosyasını düzenleyin
   - Yeni UI bileşenleri ekleyin

3. **Test:**
   ```bash
   # Geliştirme modunda çalıştır
   python app.py
   
   # Docker ile test et
   docker-compose up --build
   ```

## 🔒 Güvenlik

### Önemli Notlar

- ⚠️ **Yasal Uyarı**: Bu aracı sadece kendi sistemlerinizde veya izin verilen sistemlerde kullanın
- 🛡️ **Güvenlik**: Port tarama saldırı olarak algılanabilir, dikkatli kullanın
- 📝 **Loglama**: Tüm tarama işlemleri loglanır
- ⏱️ **Rate Limiting**: Çok hızlı tarama yapmaktan kaçının

### Güvenlik Önerileri

1. **Timeout Ayarları**: Çok düşük timeout değerleri kullanmayın
2. **Thread Sayısı**: Sistem kaynaklarını aşırı yüklemeyin
3. **Port Aralığı**: Gereksiz portları taramaktan kaçının
4. **Ağ Trafiği**: Büyük port aralıkları ağ trafiğini artırır

## 🐛 Sorun Giderme

### Yaygın Sorunlar

**1. Port 5000 kullanımda:**
```bash
# Farklı port kullanın
docker-compose up -d
# veya
python app.py --port 8080
```

**2. Docker build hatası:**
```bash
# Docker cache'ini temizleyin
docker system prune -a
docker-compose build --no-cache
```

**3. Bağlantı hatası:**
```bash
# Firewall ayarlarını kontrol edin
# Antivirus yazılımını geçici olarak devre dışı bırakın
```

**4. Yavaş tarama:**
- Thread sayısını artırın
- Timeout değerini düşürün
- Port aralığını küçültün

### Log Dosyaları

```bash
# Docker loglarını görüntüle
docker-compose logs -f

# Uygulama logları
tail -f logs/app.log
```

## 📈 Performans

### Optimizasyon İpuçları

1. **Thread Sayısı**: CPU çekirdek sayısına göre ayarlayın
2. **Timeout**: Ağ hızına göre optimize edin
3. **Port Aralığı**: Hedef odaklı tarama yapın
4. **Sistem Kaynakları**: RAM ve CPU kullanımını izleyin

### Performans Metrikleri

| Port Aralığı | Thread | Ortalama Süre |
|--------------|--------|---------------|
| 1-1024 | 100 | ~10-30 saniye |
| 1-65535 | 100 | ~5-10 dakika |
| 1-1024 | 200 | ~5-15 saniye |

## 🤝 Katkıda Bulunma

1. **Fork yapın**
2. **Feature branch oluşturun** (`git checkout -b feature/amazing-feature`)
3. **Değişikliklerinizi commit edin** (`git commit -m 'Add amazing feature'`)
4. **Branch'inizi push edin** (`git push origin feature/amazing-feature`)
5. **Pull Request oluşturun**

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 🙏 Teşekkürler

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap](https://getbootstrap.com/) - CSS framework
- [Font Awesome](https://fontawesome.com/) - İkonlar
- [OpenPyXL](https://openpyxl.readthedocs.io/) - Excel işlemleri

## 📞 İletişim

- **GitHub**: [@kullaniciadi](https://github.com/kullaniciadi)
- **Email**: kullanici@example.com
- **Proje Linki**: [https://github.com/kullaniciadi/port-scanner](https://github.com/kullaniciadi/port-scanner)

---

⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın! 