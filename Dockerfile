FROM python:3.11-slim

# Sistem paketlerini güncelle ve gerekli paketleri yükle
RUN apt-get update && apt-get install -y \
    gcc \
    iputils-ping \
    net-tools \
    nmap \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizinini ayarla
WORKDIR /app

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodlarını kopyala
COPY . .

# Logs dizini oluştur
RUN mkdir -p /app/logs

# Port 5000'i aç
EXPOSE 5000

# Uygulamayı başlat
CMD ["python", "app.py"] 