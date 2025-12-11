from flask import Flask
import os

def create_app():
    app = Flask(__name__)
    
    # Конфигурация
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'tuture123')
    app.config['DATABASE_URL'] = os.getenv('DATABASE_URL')
    
    # Инициализация БД
    from .database import init_db
    init_db(app)
    
    # Регистрация blueprints
    try:
        from .routes import main
        app.register_blueprint(main.bp)
        print("✅ main routes registered")
    except ImportError as e:
        print(f"⚠️  main routes not found: {e}")
    
    try:
        from .routes import auth
        app.register_blueprint(auth.bp)
        print("✅ auth routes registered")
    except ImportError as e:
        print(f"⚠️  auth routes not found: {e}")
    
    try:
        from .routes import documents
        app.register_blueprint(documents.bp)
        print("✅ documents routes registered")
    except ImportError as e:
        print(f"⚠️  documents routes not found: {e}")
    
    try:
        from .routes import employees
        app.register_blueprint(employees.bp)
        print("✅ employees routes registered")
    except ImportError as e:
        print(f"⚠️  employees routes not found: {e}")
    
    return app

app = create_app()