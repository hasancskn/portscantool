#!/usr/bin/env python3
"""
İlk admin kullanıcısını oluşturmak için script
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from werkzeug.security import generate_password_hash
from models import get_db, User, create_tables

def create_admin_user(username, email, password):
    """Admin kullanıcısı oluşturur"""
    try:
        # Veritabanı tablolarını oluştur
        create_tables()
        
        db = next(get_db())
        
        # Kullanıcı zaten var mı kontrol et
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            print(f"❌ Hata: '{username}' kullanıcı adı veya '{email}' email adresi zaten kullanılıyor!")
            return False
        
        # Yeni admin kullanıcısı oluştur
        admin_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_active=True
        )
        
        db.add(admin_user)
        db.commit()
        
        print(f"✅ Admin kullanıcısı başarıyla oluşturuldu!")
        print(f"👤 Kullanıcı Adı: {username}")
        print(f"📧 E-posta: {email}")
        print(f"🔑 Şifre: {password}")
        print(f"👑 Rol: Admin")
        print("\n🚀 Artık sisteme giriş yapabilirsiniz!")
        
        return True
        
    except Exception as e:
        print(f"❌ Hata: {str(e)}")
        db.rollback()
        return False
    finally:
        db.close()

def main():
    print("🔐 Port Tarayıcı - Admin Kullanıcısı Oluşturma")
    print("=" * 50)
    
    # Varsayılan değerler
    default_username = "admin"
    default_email = "admin@example.com"
    default_password = "admin123"
    
    print(f"Varsayılan değerler:")
    print(f"👤 Kullanıcı Adı: {default_username}")
    print(f"📧 E-posta: {default_email}")
    print(f"🔑 Şifre: {default_password}")
    
    # Kullanıcıdan onay al
    response = input("\nBu değerleri kullanmak istiyor musunuz? (E/H): ").strip().lower()
    
    if response in ['e', 'evet', 'y', 'yes']:
        username = default_username
        email = default_email
        password = default_password
    else:
        print("\nÖzel değerler girin:")
        username = input("👤 Kullanıcı Adı: ").strip()
        email = input("📧 E-posta: ").strip()
        password = input("🔑 Şifre: ").strip()
        
        if not username or not email or not password:
            print("❌ Tüm alanlar gereklidir!")
            return
    
    # Şifre uzunluğu kontrolü
    if len(password) < 6:
        print("❌ Şifre en az 6 karakter olmalıdır!")
        return
    
    print(f"\n🔄 Admin kullanıcısı oluşturuluyor...")
    success = create_admin_user(username, email, password)
    
    if success:
        print("\n🎉 İşlem tamamlandı! Sistemi başlatabilirsiniz.")
    else:
        print("\n💥 İşlem başarısız! Lütfen tekrar deneyin.")

if __name__ == "__main__":
    main() 