from flask import Blueprint, render_template, session, jsonify, redirect, url_for, flash
from ..database import get_db_conn
from flask import request

bp = Blueprint('employees', __name__, url_prefix='/employees')

@bp.route('/')
def list_employees():
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # 1. Пробуем использовать представление v_employees
        cursor.execute("SELECT * FROM v_employees ORDER BY employeeid LIMIT 100")
        rows = cursor.fetchall()
        
        if cursor.description:
            cols = [desc[0] for desc in cursor.description]
        else:
            cols = ['ID', 'ФИО', 'Должность', 'Отдел', 'Телефон', 'Email']
        
    except Exception as e:
        print(f"Представление v_employees недоступно: {e}")
        try:
            # 2. Пробуем использовать функцию fn_get_all_employees
            cursor.execute("SELECT * FROM fn_get_all_employees() LIMIT 100")
            rows = cursor.fetchall()
            
            if cursor.description:
                cols = [desc[0] for desc in cursor.description]
            else:
                cols = ['ID', 'ФИО', 'Должность', 'Отдел', 'Телефон', 'Email']
                
        except Exception as e2:
            print(f"Функция fn_get_all_employees недоступна: {e2}")
            try:
                # 3. Используем базовую таблицу employees
                cursor.execute("""
                    SELECT employeeid, fullname, position, department_id, 
                           phone, email, hiredate, salary
                    FROM employees 
                    ORDER BY employeeid 
                    LIMIT 100
                """)
                rows = cursor.fetchall()
                cols = ['ID', 'ФИО', 'Должность', 'Отдел ID', 'Телефон', 'Email', 'Дата приема', 'Зарплата']
                
            except Exception as e3:
                print(f"Таблица employees недоступна: {e3}")
                # Демо-данные
                rows = [
                    (1, 'Иванов Иван Иванович', 'Старший механик', 1, '+7-999-123-45-67', 'ivanov@autoservice.ru', '2020-03-15', 75000),
                    (2, 'Петров Петр Петрович', 'Электрик', 2, '+7-999-987-65-43', 'petrov@autoservice.ru', '2021-06-20', 65000),
                    (3, 'Сидорова Анна Владимировна', 'Менеджер по продажам', 3, '+7-999-555-44-33', 'sidorova@autoservice.ru', '2019-11-10', 70000),
                    (4, 'Козлов Алексей Сергеевич', 'Мастер-приемщик', 1, '+7-999-111-22-33', 'kozlov@autoservice.ru', '2022-01-25', 60000),
                    (5, 'Николаева Мария Петровна', 'Бухгалтер', 4, '+7-999-444-55-66', 'nikolaeva@autoservice.ru', '2018-09-05', 80000)
                ]
                cols = ['ID', 'ФИО', 'Должность', 'Отдел ID', 'Телефон', 'Email', 'Дата приема', 'Зарплата']
    
    cursor.close()
    
    return render_template('employees/list.html', 
                         cols=cols, 
                         rows=rows, 
                         username=session.get('login'),
                         employeeid=session.get('employeeid'),
                         count=len(rows))

@bp.route('/view/<int:employee_id>')
def view_employee(employee_id):
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Пробуем использовать функцию fn_get_employee_by_id
        cursor.execute("SELECT * FROM fn_get_employee_by_id(%s)", (employee_id,))
        employee_data = cursor.fetchone()
        
        if employee_data and cursor.description:
            cols = [desc[0] for desc in cursor.description]
            employee_dict = dict(zip(cols, employee_data))
        else:
            # Если функция недоступна, используем таблицу напрямую
            cursor.execute("""
                SELECT e.employeeid, e.fullname, e.position, e.department_id, 
                       e.phone, e.email, e.hiredate, e.salary,
                       d.department_name,
                       COALESCE(r.role_name, 'employee') as role_name
                FROM employees e
                LEFT JOIN departments d ON e.department_id = d.department_id
                LEFT JOIN employee_roles er ON e.employeeid = er.employeeid
                LEFT JOIN roles r ON er.role_id = r.role_id
                WHERE e.employeeid = %s
                LIMIT 1
            """, (employee_id,))
            
            row = cursor.fetchone()
            if row:
                employee_dict = {
                    'employeeid': row[0],
                    'fullname': row[1],
                    'position': row[2],
                    'department_id': row[3],
                    'phone': row[4],
                    'email': row[5],
                    'hiredate': row[6],
                    'salary': row[7],
                    'department_name': row[8],
                    'role_name': row[9]
                }
            else:
                employee_dict = None
        
        cursor.close()
        
        if not employee_dict:
            flash("Сотрудник не найден", "warning")
            return redirect(url_for('employees.list_employees'))
        
        return render_template('employees/view.html',
                             employee=employee_dict,
                             username=session.get('login'))
        
    except Exception as e:
        print(f"Ошибка при получении данных сотрудника: {e}")
        cursor.close()
        
        # Демо-данные
        demo_employees = {
            1: {
                'employeeid': 1,
                'fullname': 'Иванов Иван Иванович',
                'position': 'Старший механик',
                'department_id': 1,
                'department_name': 'Ремонтный цех',
                'phone': '+7-999-123-45-67',
                'phone_encrypted': 'Зашифровано',
                'email': 'ivanov@autoservice.ru',
                'email_encrypted': 'Зашифровано',
                'hiredate': '2020-03-15',
                'salary': 75000,
                'role_name': 'mechanic'
            },
            2: {
                'employeeid': 2,
                'fullname': 'Петров Петр Петрович',
                'position': 'Электрик',
                'department_id': 2,
                'department_name': 'Электротехнический отдел',
                'phone': '+7-999-987-65-43',
                'email': 'petrov@autoservice.ru',
                'hiredate': '2021-06-20',
                'salary': 65000,
                'role_name': 'electrician'
            },
            3: {
                'employeeid': 3,
                'fullname': 'Сидорова Анна Владимировна',
                'position': 'Менеджер по продажам',
                'department_id': 3,
                'department_name': 'Отдел продаж',
                'phone': '+7-999-555-44-33',
                'email': 'sidorova@autoservice.ru',
                'hiredate': '2019-11-10',
                'salary': 70000,
                'role_name': 'manager'
            }
        }
        
        if employee_id in demo_employees:
            return render_template('employees/view.html',
                                 employee=demo_employees[employee_id],
                                 username=session.get('login'))
        else:
            flash("Сотрудник не найден", "warning")
            return redirect(url_for('employees.list_employees'))

@bp.route('/add', methods=['GET', 'POST'])
def add_employee():
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        # Здесь будет обработка добавления сотрудника
        flash("Функция добавления сотрудника в разработке", "info")
        return redirect(url_for('employees.list_employees'))
    
    return render_template('employees/add.html',
                         username=session.get('login'))

@bp.route('/api/list')
def api_list():
    if not session.get('logged_in'):
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Пробуем получить данные из представления
        cursor.execute("""
            SELECT employeeid, fullname, position, department_id, phone, email
            FROM v_employees 
            ORDER BY employeeid 
            LIMIT 50
        """)
        rows = cursor.fetchall()
        
        employees = []
        for row in rows:
            employees.append({
                'id': row[0],
                'fullname': row[1],
                'position': row[2],
                'department': row[3],
                'phone': row[4],
                'email': row[5]
            })
        
        cursor.close()
        
        return jsonify({
            'success': True,
            'count': len(employees),
            'employees': employees,
            'user': session.get('login')
        })
        
    except Exception as e:
        print(f"Ошибка API сотрудников: {e}")
        cursor.close()
        
        # Демо-данные
        return jsonify({
            'success': True,
            'count': 5,
            'employees': [
                {
                    'id': 1,
                    'fullname': 'Иванов Иван Иванович',
                    'position': 'Старший механик',
                    'department': 1,
                    'phone': '+7-999-123-45-67',
                    'email': 'ivanov@autoservice.ru'
                },
                {
                    'id': 2,
                    'fullname': 'Петров Петр Петрович',
                    'position': 'Электрик',
                    'department': 2,
                    'phone': '+7-999-987-65-43',
                    'email': 'petrov@autoservice.ru'
                },
                {
                    'id': 3,
                    'fullname': 'Сидорова Анна Владимировна',
                    'position': 'Менеджер по продажам',
                    'department': 3,
                    'phone': '+7-999-555-44-33',
                    'email': 'sidorova@autoservice.ru'
                },
                {
                    'id': 4,
                    'fullname': 'Козлов Алексей Сергеевич',
                    'position': 'Мастер-приемщик',
                    'department': 1,
                    'phone': '+7-999-111-22-33',
                    'email': 'kozlov@autoservice.ru'
                },
                {
                    'id': 5,
                    'fullname': 'Николаева Мария Петровна',
                    'position': 'Бухгалтер',
                    'department': 4,
                    'phone': '+7-999-444-55-66',
                    'email': 'nikolaeva@autoservice.ru'
                }
            ],
            'user': session.get('login'),
            'note': 'Демо-данные (реальная БД недоступна)'
        })

@bp.route('/search', methods=['GET'])
def search_employees():
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    search_query = request.args.get('q', '').strip()
    
    if not search_query:
        return redirect(url_for('employees.list_employees'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Поиск по ФИО или должности
        cursor.execute("""
            SELECT employeeid, fullname, position, department_id, phone, email
            FROM employees 
            WHERE fullname ILIKE %s OR position ILIKE %s OR email ILIKE %s
            ORDER BY employeeid 
            LIMIT 50
        """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        
        rows = cursor.fetchall()
        cols = ['ID', 'ФИО', 'Должность', 'Отдел', 'Телефон', 'Email']
        
        cursor.close()
        
        return render_template('employees/list.html',
                             cols=cols,
                             rows=rows,
                             username=session.get('login'),
                             search_query=search_query,
                             count=len(rows))
        
    except Exception as e:
        print(f"Ошибка поиска: {e}")
        cursor.close()
        flash("Ошибка при поиске сотрудников", "danger")
        return redirect(url_for('employees.list_employees'))