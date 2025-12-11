import sys
import traceback

try:
    from app import app
    
    if __name__ == '__main__':
        print("=" * 50)
        print("🚀 AutoService System")
        print("=" * 50)
        print(f"📊 База данных: postgresql://postgres:admin@localhost:5432/radik")
        print(f"🌐 Веб-сервер: http://localhost:5000")
        print(f"🔧 Режим отладки: ВКЛЮЧЕН")
        print("=" * 50)
        
        # Проверка подключения к БД
        try:
            import psycopg2
            conn = psycopg2.connect('postgresql://postgres:admin@localhost:5432/radik')
            cursor = conn.cursor()
            cursor.execute('SELECT version()')
            version = cursor.fetchone()[0]
            cursor.execute('SELECT current_database()')
            db_name = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            print(f"✅ PostgreSQL: {version.split(',')[0]}")
            print(f"✅ База данных: {db_name}")
        except Exception as e:
            print(f"❌ Ошибка подключения к БД: {e}")
            print("⚠️  Проверьте, что PostgreSQL запущен и доступен")
        
        print("=" * 50)
        print("Нажмите Ctrl+C для остановки")
        print("=" * 50)
        
        app.run(debug=True, host='0.0.0.0', port=5000)
        
except Exception as e:
    print(f"❌ Критическая ошибка при запуске: {e}")
    traceback.print_exc()
    print("\n🔧 Возможные решения:")
    print("1. Проверьте установлены ли все зависимости: pip install -r requirements.txt")
    print("2. Проверьте запущен ли PostgreSQL на localhost:5432")
    print("3. Проверьте права доступа к БД radik")
    input("\nНажмите Enter для выхода...")
    sys.exit(1)