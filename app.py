import os
import socket
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
import tempfile
import json

app = Flask(__name__)

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
        scan_results = data.get('scan_results', {})
        
        # Excel dosyası oluştur
        wb = Workbook()
        ws = wb.active
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
        
        # Dosya adını oluştur
        filename = f"port_scan_{target_host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
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