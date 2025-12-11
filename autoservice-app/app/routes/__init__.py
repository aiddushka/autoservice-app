# Экспортируем объекты bp из каждого модуля
from .main import bp as main_bp
from .auth import bp as auth_bp
from .documents import bp as documents_bp
from .employees import bp as employees_bp

# Экспортируем как переменные
__all__ = ['main_bp', 'auth_bp', 'documents_bp', 'employees_bp']