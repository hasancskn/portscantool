import os
import socket
import threading
import time
import ipaddress
import subprocess
import platform
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
import tempfile
import json

app = Flask(__name__)

class IPScanner:
    def __init__(self, network_range, timeout=1):
        self.network_range = network_range
        self.timeout = timeout
        self.active_ips = []
        self.scanned_ips = 0
        self.total_ips = 0
        self.lock = threading.Lock()
        
    def ping_host_socket(self, ip):
        """Socket ile ping benzeri kontrol"""
        try:
            # TCP bağlantısı ile kontrol (port 80 veya 443)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Önce port 80'i dene
            result = sock.connect_ex((str(ip), 80))
            if result == 0:
                sock.close()
                return True
                
            # Port 80 kapalıysa port 443'ü dene
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), 443))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def ping_host(self, ip):
        """Tek bir IP adresini ping ile kontrol eder"""
        try:
            # Önce socket ile dene
            if self.ping_host_socket(ip):
                with self.lock:
                    self.scanned_ips += 1
                    hostname = self.get_hostname(ip)
                    self.active_ips.append({
                        'ip': str(ip),
                        'hostname': hostname,
                        'status': 'Active',
                        'response_time': 'TCP Check'
                    })
                return
            
            # Platform'a göre ping komutu
            if platform.system().lower() == "windows":
                # Windows için ping komutu - daha güvenilir
                ping_cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), str(ip)]
            else:
                # Linux/Mac için ping komutu
                ping_cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), str(ip)]
            
            # Subprocess timeout'u ping timeout'undan biraz daha uzun tut
            process_timeout = self.timeout + 3
            
            result = subprocess.run(
                ping_cmd, 
                capture_output=True, 
                text=True, 
                timeout=process_timeout,
                shell=False
            )
            
            with self.lock:
                self.scanned_ips += 1
                
                # Ping başarılı mı kontrol et
                if result.returncode == 0:
                    # Ping başarılı, host aktif
                    hostname = self.get_hostname(ip)
                    response_time = self.extract_response_time(result.stdout)
                    
                    self.active_ips.append({
                        'ip': str(ip),
                        'hostname': hostname,
                        'status': 'Active',
                        'response_time': response_time
                    })
                    
        except subprocess.TimeoutExpired:
            # Ping timeout oldu
            with self.lock:
                self.scanned_ips += 1
        except Exception as e:
            # Diğer hatalar
            with self.lock:
                self.scanned_ips += 1
                print(f"Ping error for {ip}: {str(e)}")
    
    def get_hostname(self, ip):
        """IP adresinden hostname almaya çalışır"""
        try:
            # Hostname çözümleme için timeout ayarla
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except socket.herror:
            # Hostname bulunamadı
            return "Unknown"
        except socket.timeout:
            # Timeout
            return "Timeout"
        except Exception:
            # Diğer hatalar
            return "Error"
        finally:
            # Timeout'u sıfırla
            socket.setdefaulttimeout(None)
    
    def extract_response_time(self, ping_output):
        """Ping çıktısından response time çıkarır"""
        try:
            if platform.system().lower() == "windows":
                # Windows ping formatı: "time=5ms" veya "time<1ms"
                if "time=" in ping_output:
                    time_part = ping_output.split("time=")[1].split()[0]
                    return time_part
                elif "time<" in ping_output:
                    time_part = ping_output.split("time<")[1].split()[0]
                    return f"<{time_part}"
            else:
                # Linux/Mac ping formatı: "time=5.123 ms"
                if "time=" in ping_output:
                    time_part = ping_output.split("time=")[1].split()[0]
                    return time_part + " ms"
        except:
            pass
        return "Unknown"
    
    def scan_network(self, max_threads=50):
        """Ağ taramasını başlatır"""
        try:
            # Network range'i parse et
            network = ipaddress.IPv4Network(self.network_range, strict=False)
            self.total_ips = network.num_addresses
            
            print(f"Starting network scan for {self.network_range}")
            print(f"Total IPs to scan: {self.total_ips}")
            print(f"Max threads: {max_threads}")
            
            threads = []
            
            for ip in network.hosts():
                thread = threading.Thread(target=self.ping_host, args=(ip,))
                threads.append(thread)
                thread.start()
                
                # Maksimum thread sayısını kontrol et
                if len(threads) >= max_threads:
                    for t in threads:
                        t.join()
                    threads = []
            
            # Kalan thread'leri bekle
            for t in threads:
                t.join()
            
            print(f"Scan completed. Found {len(self.active_ips)} active IPs")
            return self.active_ips, self.scanned_ips, self.total_ips
            
        except Exception as e:
            print(f"Network scan error: {str(e)}")
            raise Exception(f"Ağ tarama hatası: {str(e)}")

class PortScanner:
    def __init__(self, target_host, start_port, end_port, timeout=1):
        self.target_host = target_host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.open_ports = []
        self.scanned_ports = 0
        self.total_ports = end_port - start_port + 1
        self.lock = threading.Lock()
        
    def scan_port(self, port):
        """Tek bir portu tarar"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            
            with self.lock:
                self.scanned_ports += 1
                if result == 0:
                    self.open_ports.append({
                        'port': port,
                        'service': self.get_service_name(port),
                        'status': 'Open'
                    })
                    
        except Exception as e:
            with self.lock:
                self.scanned_ports += 1
                
    def get_service_name(self, port):
        """Port numarasına göre servis adını döndürür"""
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAP SSL',
            995: 'POP3 SSL',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Alt',
            27017: 'MongoDB'
        }
        return common_services.get(port, 'Unknown')
    
    def scan(self, max_threads=100):
        """Port taramasını başlatır"""
        threads = []
        
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Maksimum thread sayısını kontrol et
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Kalan thread'leri bekle
        for t in threads:
            t.join()
            
        return self.open_ports, self.scanned_ports, self.total_ports

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/scan-network', methods=['POST'])
def scan_network():
    """Ağ tarama API endpoint'i"""
    try:
        data = request.get_json()
        network_range = data.get('network_range')
        timeout = float(data.get('timeout', 1))
        max_threads = int(data.get('max_threads', 50))
        
        print(f"Network scan request: {network_range}, timeout: {timeout}, threads: {max_threads}")
        
        # Network range validasyonu
        try:
            ipaddress.IPv4Network(network_range, strict=False)
        except Exception:
            return jsonify({'error': 'Geçersiz ağ aralığı (örn: 192.168.1.0/24)'}), 400
        
        # Taramayı başlat
        scanner = IPScanner(network_range, timeout)
        active_ips, scanned_ips, total_ips = scanner.scan_network(max_threads)
        
        # Sonuçları hazırla
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result = {
            'network_range': network_range,
            'scan_time': scan_time,
            'total_ips': total_ips,
            'scanned_ips': scanned_ips,
            'active_ips_count': len(active_ips),
            'active_ips': active_ips
        }
        
        print(f"Scan completed: {len(active_ips)} active IPs found")
        return jsonify(result)
        
    except Exception as e:
        print(f"Network scan error: {str(e)}")
        return jsonify({'error': f'Ağ tarama hatası: {str(e)}'}), 500

@app.route('/scan', methods=['POST'])
def scan_ports():
    """Port tarama API endpoint'i"""
    try:
        data = request.get_json()
        target_host = data.get('target_host')
        start_port = int(data.get('start_port', 1))
        end_port = int(data.get('end_port', 1024))
        timeout = float(data.get('timeout', 1))
        max_threads = int(data.get('max_threads', 100))
        
        # Host adresini doğrula
        try:
            socket.gethostbyname(target_host)
        except socket.gaierror:
            return jsonify({'error': 'Geçersiz host adresi'}), 400
        
        # Port aralığını kontrol et
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return jsonify({'error': 'Geçersiz port aralığı (1-65535)'}), 400
        
        # Taramayı başlat
        scanner = PortScanner(target_host, start_port, end_port, timeout)
        open_ports, scanned_ports, total_ports = scanner.scan(max_threads)
        
        # Sonuçları hazırla
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result = {
            'target_host': target_host,
            'scan_time': scan_time,
            'start_port': start_port,
            'end_port': end_port,
            'total_ports': total_ports,
            'scanned_ports': scanned_ports,
            'open_ports_count': len(open_ports),
            'open_ports': open_ports
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Tarama hatası: {str(e)}'}), 500

@app.route('/export-excel', methods=['POST'])
def export_excel():
    """Excel dosyası oluştur ve indir"""
    try:
        data = request.get_json()
        scan_type = data.get('scan_type')  # 'network' veya 'port'
        scan_results = data.get('scan_results', {})
        
        # Excel dosyası oluştur
        wb = Workbook()
        ws = wb.active
        
        if scan_type == 'network':
            ws.title = "Ağ Tarama Sonuçları"
            
            # Başlık satırı
            headers = ['Ağ Aralığı', 'Tarama Zamanı', 'IP Adresi', 'Hostname', 'Durum', 'Response Time']
            for col, header in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col, value=header)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
                cell.font = Font(color="FFFFFF", bold=True)
                cell.alignment = Alignment(horizontal="center")
            
            # Tarama bilgileri
            row = 2
            network_range = scan_results.get('network_range', '')
            scan_time = scan_results.get('scan_time', '')
            
            active_ips = scan_results.get('active_ips', [])
            if active_ips:
                for ip_info in active_ips:
                    ws.cell(row=row, column=1, value=network_range)
                    ws.cell(row=row, column=2, value=scan_time)
                    ws.cell(row=row, column=3, value=ip_info['ip'])
                    ws.cell(row=row, column=4, value=ip_info['hostname'])
                    ws.cell(row=row, column=5, value=ip_info['status'])
                    ws.cell(row=row, column=6, value=ip_info['response_time'])
                    row += 1
            else:
                # Aktif IP yoksa bilgi satırı ekle
                ws.cell(row=row, column=1, value=network_range)
                ws.cell(row=row, column=2, value=scan_time)
                ws.cell(row=row, column=3, value="Aktif IP bulunamadı")
                ws.cell(row=row, column=4, value="-")
                ws.cell(row=row, column=5, value="Inactive")
                ws.cell(row=row, column=6, value="-")
            
            filename = f"network_scan_{network_range.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
        else:  # port scan
            ws.title = "Port Tarama Sonuçları"
            
            # Başlık satırı
            headers = ['Hedef Host', 'Tarama Zamanı', 'Port', 'Servis', 'Durum']
            for col, header in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col, value=header)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
                cell.font = Font(color="FFFFFF", bold=True)
                cell.alignment = Alignment(horizontal="center")
            
            # Tarama bilgileri
            row = 2
            target_host = scan_results.get('target_host', '')
            scan_time = scan_results.get('scan_time', '')
            
            open_ports = scan_results.get('open_ports', [])
            if open_ports:
                for port_info in open_ports:
                    ws.cell(row=row, column=1, value=target_host)
                    ws.cell(row=row, column=2, value=scan_time)
                    ws.cell(row=row, column=3, value=port_info['port'])
                    ws.cell(row=row, column=4, value=port_info['service'])
                    ws.cell(row=row, column=5, value=port_info['status'])
                    row += 1
            else:
                # Açık port yoksa bilgi satırı ekle
                ws.cell(row=row, column=1, value=target_host)
                ws.cell(row=row, column=2, value=scan_time)
                ws.cell(row=row, column=3, value="Açık port bulunamadı")
                ws.cell(row=row, column=4, value="-")
                ws.cell(row=row, column=5, value="Closed")
            
            filename = f"port_scan_{target_host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        # Sütun genişliklerini ayarla
        for column in ws.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            ws.column_dimensions[column_letter].width = adjusted_width
        
        # Geçici dosya oluştur
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp:
            wb.save(tmp.name)
            tmp_path = tmp.name
        
        return send_file(
            tmp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        return jsonify({'error': f'Excel oluşturma hatası: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 