import psycopg2
from flask import g, current_app
import os

def get_db_conn():
    if 'db_conn' not in g:
        # Получаем URL из конфига Flask или переменных окружения
        DATABASE_URL = current_app.config.get('DATABASE_URL')
        if not DATABASE_URL:
            DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:admin@localhost:5432/radik')
        
        print(f"📊 Подключаемся к БД: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")
        
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            g.db_conn = conn
            print("✅ Подключение к БД установлено")
        except Exception as e:
            print(f"❌ Ошибка подключения к БД: {e}")
            raise
    
    return g.db_conn

def init_db(app):
    """Инициализация базы данных"""
    
    @app.teardown_appcontext
    def close_conn(exc):
        conn = g.pop('db_conn', None)
        if conn is not None:
            conn.close()
            print("🔌 Соединение с БД закрыто")