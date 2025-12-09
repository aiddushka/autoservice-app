После получение репощитория к себе в директорию выолните следующие шаги:
1) Запустите Docker Desktop
2) В терминале зайдите в папку "autoservice-app\postgres-env"
3) Запустите команду docker-compose up -d
После этой команды у вас 
        1. Поднимается контейнер db
        2. Инициализируется база autoservice
        3.Docker автоматически выполняет любые скрипты в: /docker-entrypoint-initdb.d/
        4. Мы монтируем туда init/restore.sh, значит он выполнится один раз — при первом запуске контейнера.
        5. Скрипт выполняет: psql -U postgres -d autoservice < /backup/backup.sql
        6. Открывается веб интерфес postgresql
        
        Открывается тут:
        http://localhost:5050
        Логин: admin@example.com
        Пароль: admin   (это нужно для входа в pgadmin4)

        Чтобы подключиться к базе, добавь сервер:

        Host: db
        User: postgres
        Password: postgres
        DB: autoservice
(У меня по таймеру занело: 55 секунд скорость интернета: 65 мбит/с)

4) 

Пока не читай меня! Я сгенерирован ИИ.

# Autoservice API (FastAPI + PostgreSQL)

Учебный проект для работы с БД, миграциями и безопасностью.

## Запуск

```bash
docker-compose up --build
