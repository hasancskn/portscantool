import nmap
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from models import Scan, ScanResult, HostInfo, Alert, AuditLog
from config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedPortScanner:
    def __init__(self, db_session: Session):
        self.db = db_session
        self.nm = nmap.PortScanner()
        
    def scan_host(self, target_host: str, start_port: int, end_port: int, 
                  scan_type: str = 'manual', user: str = None, ip_address: str = None) -> Dict:
        """
        Nmap ile gelişmiş port taraması yapar
        """
        start_time = time.time()
        
        # Scan kaydını oluştur
        scan = Scan(
            target_host=target_host,
            start_port=start_port,
            end_port=end_port,
            scan_type=scan_type,
            status='running',
            start_time=datetime.utcnow()
        )
        self.db.add(scan)
        self.db.commit()
        
        # Audit log
        self._log_audit(scan.id, 'scan_started', user, f'Started scan for {target_host}', ip_address)
        
        try:
            # Nmap komutu oluştur
            port_range = f"{start_port}-{end_port}"
            nmap_args = f"-sV -O --script-args={Config.NMAP_SCRIPT_ARGS}"
            
            logger.info(f"Starting nmap scan: {target_host} {port_range}")
            
            # Nmap taramasını çalıştır
            self.nm.scan(target_host, port_range, arguments=nmap_args)
            
            # Sonuçları işle
            scan_results = []
            host_info = None
            all_ports_count = 0  # Taranan port sayısı
            
            for host in self.nm.all_hosts():
                # Host bilgilerini kaydet
                host_info = self._extract_host_info(host, scan.id)
                
                # Port sonuçlarını işle
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        all_ports_count += 1
                        port_info = self.nm[host][proto][port]
                        scan_result = self._extract_port_info(port_info, scan.id, port, proto)
                        scan_results.append(scan_result)
            
            # Scan kaydını güncelle
            scan_duration = time.time() - start_time
            scan.status = 'completed'
            scan.end_time = datetime.utcnow()
            scan.total_ports = end_port - start_port + 1
            scan.open_ports_count = len([r for r in scan_results if r.state == 'open'])
            scan.scan_duration = scan_duration
            scan.nmap_output = json.dumps(self.nm.analyse_nmap_xml_scan())
            
            self.db.commit()
            
            # Anomali tespiti yap
            self._detect_anomalies(scan.id, target_host, scan_results)
            
            # Audit log
            self._log_audit(scan.id, 'scan_completed', user, 
                           f'Scan completed for {target_host} in {scan_duration:.2f}s', ip_address)
            
            return {
                'scan_id': scan.id,
                'target_host': target_host,
                'total_ports': scan.total_ports,
                'scanned_ports': all_ports_count,
                'open_ports_count': scan.open_ports_count,
                'scan_duration': scan_duration,
                'host_info': host_info,
                'scan_results': scan_results
            }
            
        except Exception as e:
            logger.error(f"Scan failed for {target_host}: {str(e)}")
            scan.status = 'failed'
            scan.end_time = datetime.utcnow()
            self.db.commit()
            
            # Audit log
            self._log_audit(scan.id, 'scan_failed', user, f'Scan failed: {str(e)}', ip_address)
            
            raise e
    
    def _extract_host_info(self, host: str, scan_id: int) -> Optional[HostInfo]:
        """Host bilgilerini çıkarır"""
        try:
            host_data = self.nm[host]
            
            # OS bilgileri
            os_info = host_data.get('osmatch', [])
            os_family = os_info[0]['name'] if os_info else None
            os_version = os_info[0]['version'] if os_info and 'version' in os_info[0] else None
            os_accuracy = os_info[0]['accuracy'] if os_info else None
            
            # MAC adresi ve vendor
            mac_address = host_data.get('addresses', {}).get('mac')
            vendor = host_data.get('vendor', {}).get(mac_address) if mac_address else None
            
            host_info = HostInfo(
                scan_id=scan_id,
                ip_address=host,
                hostname=host_data.get('hostnames', [{}])[0].get('name') if host_data.get('hostnames') else None,
                os_family=os_family,
                os_version=os_version,
                os_accuracy=os_accuracy,
                mac_address=mac_address,
                vendor=vendor
            )
            
            self.db.add(host_info)
            self.db.commit()
            return host_info
            
        except Exception as e:
            logger.error(f"Error extracting host info: {str(e)}")
            return None
    
    def _extract_port_info(self, port_data: Dict, scan_id: int, port: int, protocol: str) -> ScanResult:
        """Port bilgilerini çıkarır"""
        scan_result = ScanResult(
            scan_id=scan_id,
            port=port,
            service=port_data.get('name', 'unknown'),
            version=port_data.get('version', ''),
            state=port_data.get('state', 'unknown'),
            protocol=protocol,
            banner=port_data.get('product', '') + ' ' + port_data.get('version', '')
        )
        
        self.db.add(scan_result)
        self.db.commit()
        return scan_result
    
    def _detect_anomalies(self, scan_id: int, target_host: str, current_results: List[ScanResult]):
        """Anomali tespiti yapar"""
        try:
            # Önceki taramaları al
            previous_scans = self.db.query(Scan).filter(
                Scan.target_host == target_host,
                Scan.id != scan_id,
                Scan.status == 'completed'
            ).order_by(Scan.start_time.desc()).limit(5).all()
            
            if not previous_scans:
                return
            
            # En son taramayı al
            last_scan = previous_scans[0]
            last_results = self.db.query(ScanResult).filter(
                ScanResult.scan_id == last_scan.id
            ).all()
            
            # Açık portları karşılaştır
            current_open_ports = {r.port for r in current_results if r.state == 'open'}
            last_open_ports = {r.port for r in last_results if r.state == 'open'}
            
            # Yeni açılan portlar
            new_ports = current_open_ports - last_open_ports
            for port in new_ports:
                port_result = next(r for r in current_results if r.port == port and r.state == 'open')
                self._create_alert(scan_id, 'new_port', 'high', 
                                 f'New open port detected: {port} ({port_result.service})',
                                 f'Port {port} is now open with service {port_result.service}')
            
            # Kapanan portlar
            closed_ports = last_open_ports - current_open_ports
            for port in closed_ports:
                self._create_alert(scan_id, 'closed_port', 'medium',
                                 f'Port closed: {port}',
                                 f'Port {port} is no longer open')
            
            # Servis değişiklikleri
            for current_result in current_results:
                if current_result.state == 'open':
                    last_result = next((r for r in last_results if r.port == current_result.port), None)
                    if last_result and last_result.service != current_result.service:
                        self._create_alert(scan_id, 'service_change', 'medium',
                                         f'Service changed on port {current_result.port}',
                                         f'Service changed from {last_result.service} to {current_result.service}')
                        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
    
    def _create_alert(self, scan_id: int, alert_type: str, severity: str, message: str, details: str):
        """Alarm oluşturur"""
        alert = Alert(
            scan_id=scan_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            details=details
        )
        self.db.add(alert)
        self.db.commit()
        # Email/webhook gönder
        self._send_alert(alert)
        # Alarm kurallarını değerlendir
        from alert_service import evaluate_alert_rules
        evaluate_alert_rules(alert, self.db)
    
    def _send_alert(self, alert: Alert):
        """Alarmı email veya webhook ile gönderir"""
        try:
            from alert_service import AlertService
            alert_service = AlertService()
            alert_service.send_alert(alert)
            
            alert.is_sent = True
            alert.sent_time = datetime.utcnow()
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
    
    def _log_audit(self, scan_id: int, action: str, user: str, details: str, ip_address: str):
        """Audit log kaydı oluşturur"""
        audit_log = AuditLog(
            scan_id=scan_id,
            action=action,
            user=user,
            details=details,
            ip_address=ip_address
        )
        
        self.db.add(audit_log)
        self.db.commit() 