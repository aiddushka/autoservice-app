# test_auth_fixed.py
import psycopg2
import sys
import os

def get_db_connection():
    """Подключение к базе данных"""
    DATABASE_URL = "postgresql://postgres:admin@localhost:5432/radik"
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        return conn
    except Exception as e:
        print(f"❌ Ошибка подключения к БД: {e}")
        return None

def test_database_connection():
    """Тестирование подключения к БД и проверка структуры"""
    print("=" * 60)
    print("🔍 ТЕСТ ПОДКЛЮЧЕНИЯ К БАЗЕ ДАННЫХ")
    print("=" * 60)
    
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    
    try:
        # Проверка версии PostgreSQL
        cursor.execute('SELECT version()')
        version = cursor.fetchone()[0]
        print(f"✅ PostgreSQL: {version.split(',')[0]}")
        
        # Проверка имени базы данных
        cursor.execute('SELECT current_database()')
        db_name = cursor.fetchone()[0]
        print(f"✅ База данных: {db_name}")
        
        print("\n📊 Проверка таблиц...")
        
        # Проверка таблицы employees
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'employees'
            )
        """)
        employees_exists = cursor.fetchone()[0]
        
        if employees_exists:
            print("✅ Таблица 'employees' существует")
            # Получаем структуру таблицы employees
            cursor.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'employees' 
                AND table_schema = 'public'
                ORDER BY ordinal_position
            """)
            print("   Структура таблицы employees:")
            for col_name, data_type in cursor.fetchall():
                print(f"   - {col_name}: {data_type}")
        else:
            print("❌ Таблица 'employees' не найдена")
        
        # Проверка таблицы password_history
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'password_history'
            )
        """)
        password_history_exists = cursor.fetchone()[0]
        
        if password_history_exists:
            print("\n✅ Таблица 'password_history' существует")
            # Получаем структуру таблицы password_history
            cursor.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'password_history' 
                AND table_schema = 'public'
                ORDER BY ordinal_position
            """)
            print("   Структура таблицы password_history:")
            for col_name, data_type in cursor.fetchall():
                print(f"   - {col_name}: {data_type}")
        else:
            print("\n❌ Таблица 'password_history' не найдена")
        
        # Проверка таблицы employeeaccess
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'employeeaccess'
            )
        """)
        employeeaccess_exists = cursor.fetchone()[0]
        
        if employeeaccess_exists:
            print("\n✅ Таблица 'employeeaccess' существует")
            # Получаем структуру таблицы employeeaccess
            cursor.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'employeeaccess' 
                AND table_schema = 'public'
                ORDER BY ordinal_position
            """)
            print("   Структура таблицы employeeaccess:")
            for col_name, data_type in cursor.fetchall():
                print(f"   - {col_name}: {data_type}")
        
        # Поиск пользователя z_starkov
        print("\n🔎 Поиск пользователя 'z_starkov'...")
        
        if employeeaccess_exists:
            cursor.execute("""
                SELECT ea.employeeid, ea.systemlogin, ea.isactive, 
                       e.fullname, e.position, e.department_id
                FROM employeeaccess ea
                LEFT JOIN employees e ON ea.employeeid = e.employeeid
                WHERE ea.systemlogin = 'z_starkov'
                LIMIT 1
            """)
        else:
            # Если таблицы employeeaccess нет, ищем в других таблицах
            cursor.execute("""
                SELECT employeeid, fullname, position, department_id
                FROM employees 
                WHERE email LIKE '%volkova%' OR fullname LIKE '%Волкова%'
                LIMIT 1
            """)
        
        user_data = cursor.fetchone()
        
        if user_data:
            if employeeaccess_exists:
                employeeid, login, isactive, fullname, position, dept_id = user_data
                print(f"✅ Пользователь '{login}' найден")
                print(f"   📋 ID сотрудника: {employeeid}")
                print(f"   👤 Имя: {fullname or 'Не указано'}")
                print(f"   💼 Должность: {position or 'Не указана'}")
                print(f"   🏢 Отдел: {dept_id or 'Не указан'}")
                print(f"   🟢 Активен: {'Да' if isactive else 'Нет'}")
            else:
                employeeid, fullname, position, dept_id = user_data
                print(f"✅ Сотрудник найден")
                print(f"   📋 ID: {employeeid}")
                print(f"   👤 Имя: {fullname or 'Не указано'}")
                print(f"   💼 Должность: {position or 'Не указана'}")
                print(f"   🏢 Отдел: {dept_id or 'Не указан'}")
        else:
            print("❌ Пользователь 'z_starkov' не найден")
        
        # Получение пароля из password_history
        if user_data and password_history_exists:
            employeeid = user_data[0]
            cursor.execute("""
                SELECT password_hash, change_date
                FROM password_history
                WHERE employee_id = %s
                ORDER BY change_date DESC
                LIMIT 1
            """, (employeeid,))
            
            password_data = cursor.fetchone()
            
            if password_data:
                password_hash, change_date = password_data
                print(f"\n🔑 Последний пароль в истории:")
                print(f"   📅 Дата изменения: {change_date}")
                print(f"   🔐 Хеш пароля: {password_hash[:50]}...")
                
                # Проверяем тип хеша
                if password_hash.startswith('$2'):
                    print("   🧬 Тип хеша: bcrypt")
                elif password_hash.startswith('$argon2'):
                    print("   🧬 Тип хеша: Argon2")
                elif password_hash.startswith('$6$'):
                    print("   🧬 Тип хеша: SHA-512 (crypt)")
                elif password_hash.startswith('$1$'):
                    print("   🧬 Тип хеша: MD5 (crypt)")
                else:
                    print(f"   🧬 Тип хеша: Неизвестный (префикс: {password_hash[:10]})")
            else:
                print("\n⚠️  Пароль для сотрудника не найден в таблице password_history")
        
        # Проверка всех таблиц в базе
        print("\n📋 Все таблицы в базе данных:")
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name
        """)
        
        tables = [row[0] for row in cursor.fetchall()]
        for i, table in enumerate(tables, 1):
            print(f"   {i:2}. {table}")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при проверке БД: {e}")
        cursor.close()
        conn.close()
        return False

def test_password_verification():
    """Тестирование проверки пароля"""
    print("\n" + "=" * 60)
    print("🔐 ТЕСТ ПРОВЕРКИ ПАРОЛЯ")
    print("=" * 60)
    
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    try:
        # Получаем информацию о пользователе z_starkov
        cursor.execute("""
            SELECT ea.employeeid, ea.systemlogin, e.fullname
            FROM employeeaccess ea
            LEFT JOIN employees e ON ea.employeeid = e.employeeid
            WHERE ea.systemlogin = 'z_starkov'
            LIMIT 1
        """)
        
        user = cursor.fetchone()
        
        if not user:
            print("❌ Пользователь 'z_starkov' не найден")
            cursor.close()
            conn.close()
            return
        
        employeeid, login, fullname = user
        
        print(f"👤 Тестируем пользователя: {login} ({fullname or 'без имени'})")
        print(f"   ID: {employeeid}")
        
        # Получаем последний пароль из истории
        cursor.execute("""
            SELECT password_hash
            FROM password_history
            WHERE employee_id = %s
            ORDER BY change_date DESC
            LIMIT 1
        """, (employeeid,))
        
        password_row = cursor.fetchone()
        
        if not password_row:
            print("❌ Пароль не найден в таблице password_history")
            cursor.close()
            conn.close()
            return
        
        stored_hash = password_row[0]
        print(f"🔐 Хранимый хеш: {stored_hash[:30]}...")
        
        # Тестируем разные пароли
        test_passwords = [
            ("SuperAdmin999!", "✅ Правильный пароль (ожидаемый)"),
            ("SuperAdmin999!", "❌ Неправильный регистр"),
            ("StrongPassword2", "❌ Без восклицательного знака"),
            ("StrongPassword1!", "❌ Неправильная цифра"),
            ("WrongPassword123", "❌ Совсем другой пароль"),
            ("", "❌ Пустой пароль")
        ]
        
        print("\n🧪 Проверка паролей:")
        
        for password, description in test_passwords:
            try:
                # Используем PostgreSQL crypt для проверки
                cursor.execute("""
                    SELECT crypt(%s, %s) = %s AS password_match
                """, (password, stored_hash, stored_hash))
                
                result = cursor.fetchone()[0]
                
                if result:
                    print(f"   🟢 {description}: ПАРОЛЬ СОВПАЛ")
                    if "Правильный" in description:
                        print(f"      🎉 УСПЕХ! Правильный пароль найден!")
                else:
                    print(f"   🔴 {description}: не совпал")
                    
            except Exception as e:
                # Если crypt не работает, пробуем другой метод
                print(f"   ⚠️  {description}: ошибка проверки ({str(e)[:50]})")
        
        # Дополнительная информация о хеше
        print(f"\n🔍 Анализ хеша пароля:")
        print(f"   Длина хеша: {len(stored_hash)} символов")
        
        if stored_hash.startswith('$2'):
            print("   Алгоритм: bcrypt")
            # bcrypt хеши: $2a$, $2b$, $2y$
            version = stored_hash[1:3]
            cost = stored_hash[4:6]
            print(f"   Версия: {version}")
            print(f"   Стоимость: {cost}")
        elif stored_hash.startswith('$6$'):
            print("   Алгоритм: SHA-512 (Unix crypt)")
        elif len(stored_hash) == 32:
            print("   Возможный алгоритм: MD5 (32 hex символа)")
        elif len(stored_hash) == 40:
            print("   Возможный алгоритм: SHA-1 (40 hex символов)")
        elif len(stored_hash) == 64:
            print("   Возможный алгоритм: SHA-256 (64 hex символа)")
        elif len(stored_hash) == 128:
            print("   Возможный алгоритм: SHA-512 (128 hex символов)")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка при проверке пароля: {e}")
        cursor.close()
        conn.close()

def create_test_user():
    """Создание тестового пользователя (если нужно)"""
    print("\n" + "=" * 60)
    print("👨‍💼 СОЗДАНИЕ ТЕСТОВОГО ПОЛЬЗОВАТЕЛЯ")
    print("=" * 60)
    
    answer = input("Создать тестового пользователя? (да/нет): ").strip().lower()
    
    if answer != 'да':
        return
    
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    try:
        # Проверяем максимальный ID
        cursor.execute("SELECT COALESCE(MAX(employeeid), 0) + 1 FROM employees")
        new_id = cursor.fetchone()[0]
        
        # Создаем сотрудника
        cursor.execute("""
            INSERT INTO employees (employeeid, fullname, position, department_id, hiredate)
            VALUES (%s, %s, %s, %s, CURRENT_DATE)
            RETURNING employeeid
        """, (new_id, 'Тестовый Сотрудник', 'Тестировщик', 1))
        
        employeeid = cursor.fetchone()[0]
        
        # Создаем запись в employeeaccess
        cursor.execute("""
            INSERT INTO employeeaccess (employeeid, systemlogin, isactive, issuedate)
            VALUES (%s, %s, %s, CURRENT_DATE)
        """, (employeeid, 'test_user', True))
        
        # Создаем пароль (bcrypt)
        test_password = 'TestPass123!'
        cursor.execute("SELECT crypt(%s, gen_salt('bf', 10))", (test_password,))
        password_hash = cursor.fetchone()[0]
        
        # Добавляем в историю паролей
        cursor.execute("""
            INSERT INTO password_history (employee_id, password_hash, change_date)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
        """, (employeeid, password_hash))
        
        conn.commit()
        
        print(f"\n✅ Тестовый пользователь создан:")
        print(f"   ID: {employeeid}")
        print(f"   Логин: test_user")
        print(f"   Пароль: {test_password}")
        print(f"   Хеш пароля: {password_hash[:30]}...")
        
    except Exception as e:
        print(f"❌ Ошибка при создании пользователя: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def interactive_login_test():
    """Интерактивный тест входа"""
    print("\n" + "=" * 60)
    print("🎮 ИНТЕРАКТИВНЫЙ ТЕСТ ВХОДА")
    print("=" * 60)
    
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    try:
        while True:
            print("\n" + "-" * 40)
            print("Введите 'выход' для завершения")
            login = input("Логин: ").strip()
            
            if login.lower() == 'выход':
                break
            
            # Поиск пользователя
            cursor.execute("""
                SELECT ea.employeeid, ea.systemlogin, ea.isactive, e.fullname
                FROM employeeaccess ea
                LEFT JOIN employees e ON ea.employeeid = e.employeeid
                WHERE ea.systemlogin = %s
                LIMIT 1
            """, (login,))
            
            user = cursor.fetchone()
            
            if not user:
                print(f"❌ Пользователь '{login}' не найден")
                continue
            
            employeeid, db_login, isactive, fullname = user
            
            if not isactive:
                print(f"❌ Учетная запись '{login}' отключена")
                continue
            
            password = input("Пароль: ").strip()
            
            # Получаем хеш пароля
            cursor.execute("""
                SELECT password_hash
                FROM password_history
                WHERE employee_id = %s
                ORDER BY change_date DESC
                LIMIT 1
            """, (employeeid,))
            
            password_row = cursor.fetchone()
            
            if not password_row:
                print(f"❌ Пароль для пользователя '{login}' не найден")
                continue
            
            stored_hash = password_row[0]
            
            # Проверяем пароль
            cursor.execute("""
                SELECT crypt(%s, %s) = %s AS password_match
            """, (password, stored_hash, stored_hash))
            
            password_match = cursor.fetchone()[0]
            
            if password_match:
                print(f"\n🎉 УСПЕШНЫЙ ВХОД!")
                print(f"   Добро пожаловать, {fullname or login}!")
                print(f"   ID сотрудника: {employeeid}")
                
                # Показываем дополнительную информацию
                cursor.execute("""
                    SELECT position, department_id
                    FROM employees
                    WHERE employeeid = %s
                """, (employeeid,))
                
                emp_info = cursor.fetchone()
                if emp_info:
                    position, dept_id = emp_info
                    print(f"   Должность: {position or 'Не указана'}")
                    print(f"   Отдел: {dept_id or 'Не указан'}")
            else:
                print(f"\n❌ НЕВЕРНЫЙ ПАРОЛЬ")
                print(f"   Для пользователя: {login}")
            
            print("\n" + "-" * 40)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        cursor.close()
        conn.close()

def main():
    """Основная функция"""
    print("🚀 ЗАПУСК ТЕСТА АУТЕНТИФИКАЦИИ")
    print("=" * 60)
    
    # Тест подключения к БД
    if not test_database_connection():
        print("\n❌ Не удалось подключиться к БД. Проверьте настройки.")
        return
    
    # Тест проверки пароля
    test_password_verification()
    
    # Создание тестового пользователя (опционально)
    create_test_user()
    
    # Интерактивный тест
    interactive_login_test()
    
    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)

if __name__ == "__main__":
    main()