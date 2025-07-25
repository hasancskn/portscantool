# Siber Güvenlik Port ve Ağ Tarama Uygulaması

Bu uygulama, port ve ağ taramaları yapabilen, sonuçları görsel olarak sunan, kullanıcı yönetimi ve alarm kuralları içeren modern bir web tabanlı siber güvenlik aracıdır. Hem manuel hem de zamanlanmış taramalar, anomali tespiti, alarm ve bildirimler, denetim kayıtları ve kapsamlı bir yönetim paneli sunar.

## Temel Özellikler
- **Port ve Ağ Taraması:** Çoklu hedeflere port tarama (nmap ve dahili tarayıcı ile), ağda aktif cihazları bulma.
- **Zamanlanmış Taramalar:** Belirli aralıklarla otomatik tarama ve sonuç kaydı.
- **Anomali Tespiti ve Alarm:** Şüpheli durumlarda alarm üretimi, e-posta ile bildirim.
- **Kullanıcı Yönetimi:** Admin, operasyon ve monitor rolleriyle kullanıcı ekleme, silme, şifre değiştirme.
- **Rol Tabanlı Yetkilendirme:** Her rolün erişebileceği sayfa ve işlemler sınırlandırılmıştır.
- **Audit Log:** Tüm önemli işlemler kayıt altına alınır.
- **Modern Dashboard:** Sonuçlar ve istatistikler görsel olarak sunulur (Plotly).
- **Excel Desteği:** Sonuçları Excel olarak dışa aktarabilme.
- **Docker ile Kolay Kurulum:** Tüm servisler Docker Compose ile ayağa kaldırılır.

## Teknolojiler
- **Backend:** Python (Flask), SQLAlchemy, Celery, nmap
- **Frontend:** HTML5, Bootstrap 5, Plotly.js, Vanilla JS
- **Veritabanı:** PostgreSQL
- **Diğer:** Docker, Docker Compose, Flask-Login, SMTP (e-posta)

## Kurulum
1. **Gereksinimler:**
   - Docker ve Docker Compose yüklü olmalı.
2. **Kurulum:**
   - Proje klasöründe terminal açın.
   - Aşağıdaki komutu çalıştırın:
     ```
     docker-compose up --build
     ```
   - Tüm servisler (web, worker, veritabanı) otomatik başlatılır.
3. **İlk Admin Kullanıcısı:**
   - İlk admin kullanıcı otomatik olarak oluşturulur veya `create_admin.py` scripti ile eklenir.
   - docker exec -it port-scanner-app python create_admin.py
   - Giriş bilgileri terminalde veya scriptte belirtilir.

## Kullanım
- **Web Arayüzü:**
  - Tarayıcıdan `http://localhost:5000` adresine gidin.
  - Giriş yapın (admin/operasyon/monitor rolleriyle).
  - Dashboard, zamanlanmış taramalar, tüm tarama geçmişi, alarm kuralları ve kullanıcı yönetimi menülerini kullanın.
- **Zamanlanmış Tarama:**
  - Sadece admin ve operasyon rolleri yeni tarama ekleyebilir.
  - Monitor rolü sadece görüntüleyebilir.
- **Alarm ve Bildirimler:**
  - Alarm kuralları oluşturulabilir, e-posta ile bildirim alınabilir.
- **Kullanıcı Yönetimi:**
  - Sadece admin kullanıcılar yeni kullanıcı ekleyebilir, rol atayabilir.
  - Her kullanıcı kendi şifresini değiştirebilir.

## Güvenlik ve Yetkilendirme
- Tüm işlemler oturum açmış kullanıcılarla sınırlıdır.
- Rol tabanlı erişim kontrolü uygulanır.
- Admin olmayan kullanıcılar kritik işlemleri yapamaz.
- Kendi hesabınızı silemezsiniz.

## Sıkça Sorulanlar
- **Veritabanı nerede?**
  - PostgreSQL servisi Docker içinde çalışır, veriler volume ile saklanır.
- **SMTP ayarları nerede?**
  - `config.py` dosyasında SMTP ayarlarını yapabilirsiniz.
- **Loglar nerede?**
  - Uygulama ve Celery logları Docker container'larında tutulur.

## Katkı ve Geliştirme
- Kodlarınızı forkladıktan sonra pull request gönderebilirsiniz.
- Yeni özellik önerileri ve hata bildirimleri için issue açabilirsiniz.

---

Her türlü soru ve destek için proje geliştiricisine ulaşabilirsiniz. İyi kullanımlar! 
