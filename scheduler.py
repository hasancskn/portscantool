import schedule
import time
import json
import threading
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import List
from sqlalchemy.orm import Session
from models import ScheduledScan, Scan, get_db
from scanner import AdvancedPortScanner
import logging

logger = logging.getLogger(__name__)

ISTANBUL = ZoneInfo("Europe/Istanbul")

class ScanScheduler:
    def __init__(self):
        self.running = False
        self.scheduler_thread = None
    
    def start(self):
        """Scheduler'ı başlatır"""
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("Scan scheduler started")
    
    def stop(self):
        """Scheduler'ı durdurur"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        logger.info("Scan scheduler stopped")
    
    def _run_scheduler(self):
        """Scheduler ana döngüsü"""
        # Mevcut zamanlanmış taramaları yükle
        self._load_scheduled_scans()
        
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 1 dakika bekle
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}")
                time.sleep(60)
    
    def _load_scheduled_scans(self):
        """Veritabanından zamanlanmış taramaları yükler"""
        try:
            db = next(get_db())
            scheduled_scans = db.query(ScheduledScan).filter(ScheduledScan.is_active == True).all()
            
            for scheduled_scan in scheduled_scans:
                self._schedule_scan(scheduled_scan)
            
            logger.info(f"Loaded {len(scheduled_scans)} scheduled scans")
            
        except Exception as e:
            logger.error(f"Error loading scheduled scans: {str(e)}")
        finally:
            db.close()
    
    def _schedule_scan(self, scheduled_scan: ScheduledScan):
        """Tek bir zamanlanmış taramayı planlar"""
        try:
            # Zamanlanmış tarama fonksiyonu
            def run_scheduled_scan():
                self._execute_scheduled_scan(scheduled_scan)
            
            # Schedule'a ekle
            schedule.every(scheduled_scan.schedule_interval).seconds.do(run_scheduled_scan)
            
            logger.info(f"Scheduled scan '{scheduled_scan.name}' every {scheduled_scan.schedule_interval} seconds")
            
        except Exception as e:
            logger.error(f"Error scheduling scan {scheduled_scan.name}: {str(e)}")
    
    def _execute_scheduled_scan(self, scheduled_scan: ScheduledScan):
        """Zamanlanmış taramayı çalıştırır"""
        try:
            db = next(get_db())
            from models import NetworkScan
            if scheduled_scan.scan_type == 'network':
                # Ağ taraması
                from app import IPScanner
                scanner = IPScanner(scheduled_scan.network_range)
                active_ips, scanned_ips, total_ips = scanner.scan_network()
                # NetworkScan tablosuna kaydet
                network_scan = NetworkScan(
                    network_range=scheduled_scan.network_range,
                    active_ip_count=len(active_ips),
                    scan_type='scheduled',
                    created_at=datetime.now()
                )
                db.add(network_scan)
                db.commit()
                # Zamanlanmış tarama kaydını güncelle
                scheduled_scan.last_run = datetime.now()
                scheduled_scan.next_run = datetime.now() + timedelta(seconds=scheduled_scan.schedule_interval)
                db.merge(scheduled_scan)
                db.commit()
                return
            
            # Hedef hostları parse et
            target_hosts = json.loads(scheduled_scan.target_hosts)
            port_range = scheduled_scan.port_range.split('-')
            start_port = int(port_range[0])
            end_port = int(port_range[1])
            
            logger.info(f"Executing scheduled scan '{scheduled_scan.name}' for {len(target_hosts)} hosts")
            
            scanner = AdvancedPortScanner(db)
            
            # Her host için tarama yap
            for host in target_hosts:
                try:
                    result = scanner.scan_host(
                        target_host=host,
                        start_port=start_port,
                        end_port=end_port,
                        scan_type='scheduled',
                        user='system',
                        ip_address='127.0.0.1'
                    )
                    
                    logger.info(f"Scheduled scan completed for {host}: {result['open_ports_count']} open ports")
                    
                except Exception as e:
                    logger.error(f"Error in scheduled scan for {host}: {str(e)}")
            
            # Zamanlanmış tarama kaydını güncelle
            scheduled_scan.last_run = datetime.now()
            scheduled_scan.next_run = datetime.now() + timedelta(seconds=scheduled_scan.schedule_interval)
            db.merge(scheduled_scan)
            db.commit()
            
            logger.info(f"Scheduled scan '{scheduled_scan.name}' completed successfully")
            
        except Exception as e:
            logger.error(f"Error executing scheduled scan {scheduled_scan.name}: {str(e)}")
        finally:
            db.close()
    
    def add_scheduled_scan(self, name: str, scan_type: str, target_hosts: list, port_range: str, network_range: str, schedule_interval: int) -> bool:
        """Yeni zamanlanmış tarama ekler"""
        try:
            db = next(get_db())
            scheduled_scan = ScheduledScan(
                name=name,
                scan_type=scan_type,
                target_hosts=json.dumps(target_hosts) if scan_type == 'port' else '[]',
                port_range=port_range if scan_type == 'port' else None,
                network_range=network_range if scan_type == 'network' else None,
                schedule_interval=schedule_interval,
                is_active=True,
                next_run=datetime.now() + timedelta(seconds=schedule_interval),
                created_at=datetime.now()
            )
            db.add(scheduled_scan)
            db.commit()
            self._schedule_scan(scheduled_scan)
            logger.info(f"Added new scheduled scan: {name}")
            return True
        except Exception as e:
            logger.error(f"Error adding scheduled scan: {str(e)}")
            return False
        finally:
            db.close()

    def remove_scheduled_scan(self, scan_id: int) -> bool:
        """Zamanlanmış taramayı kaldırır (hard delete)"""
        try:
            db = next(get_db())
            scheduled_scan = db.query(ScheduledScan).filter(ScheduledScan.id == scan_id).first()
            if scheduled_scan:
                db.delete(scheduled_scan)
                db.commit()
                logger.info(f"Removed scheduled scan: {scheduled_scan.name}")
                return True
            else:
                logger.warning(f"Scheduled scan with ID {scan_id} not found")
                return False
        except Exception as e:
            logger.error(f"Error removing scheduled scan: {str(e)}")
            return False
        finally:
            db.close()

    def get_scheduled_scans(self) -> list:
        """Tüm zamanlanmış taramaları döndürür"""
        try:
            db = next(get_db())
            scheduled_scans = db.query(ScheduledScan).filter(ScheduledScan.is_active == True).all()
            result = []
            for scan in scheduled_scans:
                result.append({
                    'id': scan.id,
                    'name': scan.name,
                    'scan_type': scan.scan_type,
                    'target_hosts': json.loads(scan.target_hosts) if scan.target_hosts else [],
                    'port_range': scan.port_range,
                    'network_range': scan.network_range,
                    'schedule_interval': scan.schedule_interval,
                    'last_run': scan.last_run.isoformat() if scan.last_run else None,
                    'next_run': scan.next_run.isoformat() if scan.next_run else None,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None
                })
            return result
        except Exception as e:
            logger.error(f"Error getting scheduled scans: {str(e)}")
            return []
        finally:
            db.close()

# Global scheduler instance
scheduler = ScanScheduler() 