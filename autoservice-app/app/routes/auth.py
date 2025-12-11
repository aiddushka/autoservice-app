from flask import Blueprint, request, render_template, redirect, url_for, session, flash

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Просто входим как e_volkova без проверки пароля
        # В реальном приложении здесь должна быть проверка в БД
        
        # Фиктивные данные пользователя e_volkova
        user_data = {
            'employeeid': 2,
            'login': 'e_volkova',
            'fullname': 'Елена Волкова',
            'department_id': 1,
            'role': 'manager',
            'position': 'Менеджер автосервиса'
        }
        
        # Сохраняем в сессии
        session.clear()
        session['logged_in'] = True
        session['employeeid'] = user_data['employeeid']
        session['login'] = user_data['login']
        session['fullname'] = user_data['fullname']
        session['department_id'] = user_data['department_id']
        session['role'] = user_data['role']
        session['position'] = user_data['position']
        
        flash(f"Добро пожаловать, {user_data['fullname']}!", "success")
        return redirect(url_for('main.index'))
    
    return render_template('login.html')

@bp.route('/logout')
def logout():
    session.clear()
    flash("Вы вышли из системы", "info")
    return redirect(url_for('auth.login'))