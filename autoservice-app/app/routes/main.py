from flask import Blueprint, render_template, jsonify, session
import json
import os

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    # Информация о системе
    system_info = {
        "application": "AutoService Management System",
        "version": "1.0.0",
        "status": "online",
        "database": {
            "type": "PostgreSQL",
            "name": "radik",
            "status": "connected"
        },
        "authentication": {
            "enabled": True,
            "current_user": session.get('login') if session.get('logged_in') else None,
            "session_active": session.get('logged_in', False)
        },
        "modules": {
            "employees": "Управление сотрудниками",
            "documents": "Работа с документами",
            "clients": "Клиентская база (в разработке)",
            "services": "Услуги и прайс-лист (в разработке)"
        }
    }
    
    # Если пользователь вошел - добавляем его данные
    if session.get('logged_in'):
        user_data = {
            "user": {
                "id": session.get('employeeid'),
                "login": session.get('login'),
                "full_name": session.get('fullname'),
                "role": session.get('role'),
                "position": session.get('position'),
                "department_id": session.get('department_id')
            },
            "permissions": {
                "view_employees": True,
                "edit_employees": session.get('role') in ['admin', 'manager'],
                "view_documents": True,
                "edit_documents": session.get('role') in ['admin', 'manager'],
                "admin_access": session.get('role') == 'admin'
            }
        }
        system_info.update(user_data)
    
    # Форматируем JSON
    json_str = json.dumps(system_info, indent=2, ensure_ascii=False)
    
    return render_template('index.html', 
                         json_data=json_str if session.get('logged_in') else None,
                         username=session.get('login'),
                         fullname=session.get('fullname'),
                         role=session.get('role'))

@bp.route('/health')
def health():
    """Статус системы"""
    return jsonify({
        "status": "healthy",
        "timestamp": "2025-12-11T14:30:00Z",  # В реальном приложении используйте datetime
        "services": {
            "web_server": "running",
            "database": "connected",
            "authentication": "enabled"
        }
    })