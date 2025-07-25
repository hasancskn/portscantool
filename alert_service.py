import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from models import Alert
from config import Config
import logging
from models import AlertRule

logger = logging.getLogger(__name__)

class AlertService:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_username = Config.SMTP_USERNAME
        self.smtp_password = Config.SMTP_PASSWORD
        self.alert_email = Config.ALERT_EMAIL
        self.webhook_url = Config.WEBHOOK_URL
    
    def send_alert(self, alert: Alert):
        """Alarmı email ve webhook ile gönderir"""
        try:
            # Email gönder
            self._send_email_alert(alert)
            
            # Webhook gönder
            self._send_webhook_alert(alert)
            
            logger.info(f"Alert sent successfully: {alert.message}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
            raise e
    
    def _send_email_alert(self, alert: Alert):
        """Email alarmı gönderir"""
        if not self.smtp_username or self.smtp_username == 'your-email@gmail.com':
            logger.warning("Email configuration not set, skipping email alert")
            return
        
        try:
            # Email içeriği oluştur
            subject = f"Port Scanner Alert - {alert.alert_type.upper()}"
            
            body = f"""
            <html>
            <body>
                <h2>🚨 Port Scanner Alert</h2>
                <p><strong>Alert Type:</strong> {alert.alert_type}</p>
                <p><strong>Severity:</strong> {alert.severity}</p>
                <p><strong>Message:</strong> {alert.message}</p>
                <p><strong>Details:</strong> {alert.details}</p>
                <p><strong>Time:</strong> {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <p><em>This alert was generated by the Advanced Port Scanner system.</em></p>
            </body>
            </html>
            """
            
            # Email oluştur
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.smtp_username
            msg['To'] = self.alert_email
            
            # HTML içeriği ekle
            html_part = MIMEText(body, 'html')
            msg.attach(html_part)
            
            # Email gönder
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {self.alert_email}")
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            raise e
    
    def _send_webhook_alert(self, alert: Alert):
        """Webhook alarmı gönderir"""
        if not self.webhook_url or self.webhook_url == 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK':
            logger.warning("Webhook configuration not set, skipping webhook alert")
            return
        
        try:
            # Slack webhook payload
            payload = {
                "text": "🚨 Port Scanner Alert",
                "attachments": [
                    {
                        "color": self._get_severity_color(alert.severity),
                        "fields": [
                            {
                                "title": "Alert Type",
                                "value": alert.alert_type,
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": alert.severity,
                                "short": True
                            },
                            {
                                "title": "Message",
                                "value": alert.message,
                                "short": False
                            },
                            {
                                "title": "Details",
                                "value": alert.details,
                                "short": False
                            },
                            {
                                "title": "Time",
                                "value": alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                                "short": True
                            }
                        ],
                        "footer": "Advanced Port Scanner System"
                    }
                ]
            }
            
            # Webhook gönder
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Webhook alert sent successfully")
            else:
                logger.error(f"Webhook alert failed with status code: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
            raise e
    
    def _get_severity_color(self, severity: str) -> str:
        """Severity'ye göre renk döndürür"""
        colors = {
            'low': '#36a64f',      # Yeşil
            'medium': '#ffa500',   # Turuncu
            'high': '#ff8c00',     # Koyu turuncu
            'critical': '#ff0000'  # Kırmızı
        }
        return colors.get(severity, '#808080')  # Varsayılan gri
    
    def send_test_alert(self):
        """Test alarmı gönderir"""
        test_alert = Alert(
            scan_id=0,
            alert_type='test',
            severity='medium',
            message='This is a test alert from the Advanced Port Scanner system',
            details='Test alert to verify email and webhook configurations are working correctly.'
        )
        test_alert.created_at = datetime.utcnow()
        
        self.send_alert(test_alert) 

def evaluate_alert_rules(alert, db):
    rules = db.query(AlertRule).filter(AlertRule.is_active == True).all()
    for rule in rules:
        cond = rule.get_condition_dict()
        field = cond.get('field')
        operator = cond.get('operator')
        value = cond.get('value')
        alert_value = getattr(alert, field, None)
        if alert_value is None:
            continue
        match = False
        try:
            if operator == '>':
                match = float(alert_value) > float(value)
            elif operator == '<':
                match = float(alert_value) < float(value)
            elif operator == '=':
                match = str(alert_value) == str(value)
            elif operator == '!=':
                match = str(alert_value) != str(value)
            elif operator == 'contains':
                match = str(value) in str(alert_value)
        except Exception:
            continue
        if match:
            if rule.action == 'email':
                AlertService()._send_email_alert(alert)
            elif rule.action == 'webhook':
                AlertService()._send_webhook_alert(alert)
            # dashboard için burada ek aksiyon alınabilir 