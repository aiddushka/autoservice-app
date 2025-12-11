from flask import Blueprint, render_template, session, redirect, url_for, request, flash, send_file, jsonify
from ..database import get_db_conn
import io

bp = Blueprint('documents', __name__, url_prefix='/documents')

# Список документов
@bp.route('/')
def list_documents():
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Сначала пробуем использовать представление v_confidential_documents
        cursor.execute("""
            SELECT docid, doctitle, accesslevel, createddate, department_id, creatorid 
            FROM v_confidential_documents 
            ORDER BY createddate DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()
        
    except Exception as e:
        print(f"Представление v_confidential_documents недоступно: {e}")
        try:
            # Если представления нет, используем таблицу confidentialdocuments
            cursor.execute("""
                SELECT docid, doctitle, accesslevel, createddate, department_id, creatorid 
                FROM confidentialdocuments 
                ORDER BY createddate DESC
                LIMIT 50
            """)
            rows = cursor.fetchall()
        except Exception as e2:
            print(f"Таблица confidentialdocuments недоступна: {e2}")
            # Демо-данные
            rows = [
                (1, 'Регламент ТО автомобилей', 'Internal', '2024-01-15 10:30:00', 1, 1),
                (2, 'Договор с поставщиком запчастей', 'Confidential', '2024-01-14 14:20:00', 2, 2),
                (3, 'Отчет о прибыли за декабрь 2024', 'TopSecret', '2024-01-10 09:15:00', 1, 3),
                (4, 'Инструкция по технике безопасности', 'Public', '2024-01-05 11:45:00', 3, 1),
                (5, 'Штатное расписание', 'Confidential', '2024-01-02 16:30:00', 2, 2)
            ]
    
    cursor.close()
    
    return render_template('documents/list.html', 
                         documents=rows, 
                         username=session.get('login'),
                         employeeid=session.get('employeeid'),
                         department_id=session.get('department_id'))

# Просмотр документа
@bp.route('/view/<int:docid>')
def view_document(docid):
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Получаем документ
        cursor.execute("""
            SELECT doctitle, content, content_encrypted, accesslevel, createddate, creatorid
            FROM confidentialdocuments 
            WHERE docid = %s 
            LIMIT 1
        """, (docid,))
        
        row = cursor.fetchone()
        
        if not row:
            cursor.close()
            flash("Документ не найден", "warning")
            return redirect(url_for('documents.list_documents'))
        
        doctitle, content, content_encrypted, accesslevel, createddate, creatorid = row
        
        # Пытаемся расшифровать если есть зашифрованное содержимое
        decrypted_content = None
        if content_encrypted is not None:
            try:
                # Пробуем использовать decrypt_data
                cursor.execute("SELECT decrypt_data(%s);", (content_encrypted,))
                result = cursor.fetchone()
                if result and result[0] is not None:
                    decrypted_content = result[0]
            except Exception:
                try:
                    # Пробуем pgp_sym_decrypt
                    cursor.execute("SELECT pgp_sym_decrypt(%s, get_encryption_key())::text;", (content_encrypted,))
                    result = cursor.fetchone()
                    if result and result[0] is not None:
                        decrypted_content = result[0]
                except Exception as e:
                    print(f"Не удалось расшифровать: {e}")
                    decrypted_content = "[Содержимое зашифровано. Требуются права доступа]"
        
        # Определяем отображаемое содержимое
        display_content = decrypted_content if decrypted_content is not None else content
        
        cursor.close()
        
        return render_template('documents/view.html',
                             docid=docid,
                             title=doctitle,
                             content=display_content,
                             accesslevel=accesslevel,
                             createddate=createddate,
                             creatorid=creatorid,
                             employeeid=session.get('employeeid'))
        
    except Exception as e:
        print(f"Ошибка при просмотре документа: {e}")
        cursor.close()
        
        # Демо-контент для теста
        demo_documents = {
            1: {
                'title': 'Регламент ТО автомобилей',
                'content': '''# РЕГЛАМЕНТ ТЕХНИЧЕСКОГО ОБСЛУЖИВАНИЯ

## 1. Периодичность ТО
- Каждые 10,000 км или 1 раз в год
- Проверка масла и фильтров
- Диагностика ходовой части

## 2. Обязательные работы
1. Замена масла двигателя
2. Замена воздушного фильтра
3. Проверка тормозной системы
4. Диагностика электроники

## 3. Требования к качеству
Все работы должны выполняться сертифицированными специалистами.
Используются только оригинальные запчасти или аналоги надлежащего качества.''',
                'accesslevel': 'Internal'
            },
            2: {
                'title': 'Договор с поставщиком запчастей',
                'content': '''ДОГОВОР № 245/2024
о поставке автозапчастей

г. Москва                           «15» января 2024 г.

ООО "АвтоСервис Плюс", именуемое в дальнейшем "Покупатель", и ООО "АвтоДеталь", именуемое в дальнейшем "Поставщик", заключили настоящий договор о нижеследующем:

1. Предмет договора
1.1. Поставщик обязуется поставлять, а Покупатель - принимать и оплачивать автозапчасти согласно приложениям.

2. Сроки поставки
2.1. Поставка осуществляется в течение 3 рабочих дней с момента подтверждения заказа.

3. Цена и порядок расчетов
3.1. Цены устанавливаются согласно прейскуранту Поставщика.
3.2. Оплата производится в течение 10 банковских дней с момента поставки.''',
                'accesslevel': 'Confidential'
            },
            3: {
                'title': 'Отчет о прибыли за декабрь 2024',
                'content': '''ФИНАНСОВЫЙ ОТЧЕТ
за декабрь 2024 года

## Доходы:
- Ремонтные работы: 1,250,000 ₽
- ТО и диагностика: 450,000 ₽
- Продажа запчастей: 320,000 ₽
- Консультации: 75,000 ₽
**Итого доход: 2,095,000 ₽**

## Расходы:
- Зарплата сотрудников: 850,000 ₽
- Аренда помещения: 150,000 ₽
- Коммунальные услуги: 45,000 ₽
- Закупка запчастей: 680,000 ₽
- Налоги: 210,000 ₽
**Итого расходы: 1,935,000 ₽**

## Чистая прибыль: 160,000 ₽

Примечание: Рост прибыли на 15% по сравнению с ноябрем 2024.''',
                'accesslevel': 'TopSecret'
            }
        }
        
        if docid in demo_documents:
            doc = demo_documents[docid]
            return render_template('documents/view.html',
                                 docid=docid,
                                 title=doc['title'],
                                 content=doc['content'],
                                 accesslevel=doc['accesslevel'],
                                 createddate='2024-01-15 10:30:00',
                                 creatorid=1,
                                 employeeid=session.get('employeeid'))
        else:
            flash("Документ не найден", "warning")
            return redirect(url_for('documents.list_documents'))

# Загрузка документа
@bp.route('/upload', methods=['GET', 'POST'])
def upload_document():
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        accesslevel = request.form.get('accesslevel', 'Internal')
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
        
        if not title:
            flash("Введите название документа", "warning")
            return render_template('documents/upload.html')
        
        if not content and not file:
            flash("Введите содержимое или загрузите файл", "warning")
            return render_template('documents/upload.html')
        
        conn = get_db_conn()
        cursor = conn.cursor()
        
        try:
            employeeid = session.get('employeeid', 1)
            department_id = session.get('department_id', 1)
            
            if file:
                # Если загружен файл, читаем его содержимое
                file_content = file.read()
                
                # Пробуем использовать функцию fn_insert_confidential_document
                try:
                    cursor.execute("""
                        SELECT fn_insert_confidential_document(%s, %s, %s, %s, %s)
                    """, (title, employeeid, file_content, accesslevel, department_id))
                    
                    cursor.execute("SELECT lastval()")
                    docid = cursor.fetchone()[0]
                    
                except Exception:
                    # Если функция недоступна, вставляем напрямую
                    try:
                        # Пробуем зашифровать
                        cursor.execute("SELECT encrypt_data(%s)", (file_content,))
                        encrypted = cursor.fetchone()[0]
                        
                        cursor.execute("""
                            INSERT INTO confidentialdocuments 
                            (doctitle, creatorid, content_encrypted, accesslevel, department_id)
                            VALUES (%s, %s, %s, %s, %s)
                            RETURNING docid
                        """, (title, employeeid, encrypted, accesslevel, department_id))
                        
                        docid = cursor.fetchone()[0]
                        
                    except Exception:
                        # Простая вставка
                        cursor.execute("""
                            INSERT INTO confidentialdocuments 
                            (doctitle, creatorid, content, accesslevel, department_id)
                            VALUES (%s, %s, %s, %s, %s)
                            RETURNING docid
                        """, (title, employeeid, file_content.decode('utf-8', errors='replace'), accesslevel, department_id))
                        
                        docid = cursor.fetchone()[0]
            else:
                # Текстовое содержимое
                try:
                    # Пробуем зашифровать текст
                    cursor.execute("SELECT encrypt_data(%s)", (content.encode(),))
                    encrypted = cursor.fetchone()[0]
                    
                    cursor.execute("""
                        INSERT INTO confidentialdocuments 
                        (doctitle, creatorid, content_encrypted, accesslevel, department_id)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING docid
                    """, (title, employeeid, encrypted, accesslevel, department_id))
                    
                    docid = cursor.fetchone()[0]
                    
                except Exception:
                    # Простая вставка текста
                    cursor.execute("""
                        INSERT INTO confidentialdocuments 
                        (doctitle, creatorid, content, accesslevel, department_id)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING docid
                    """, (title, employeeid, content, accesslevel, department_id))
                    
                    docid = cursor.fetchone()[0]
            
            conn.commit()
            flash(f"Документ '{title}' успешно добавлен (ID: {docid})", "success")
            cursor.close()
            return redirect(url_for('documents.list_documents'))
            
        except Exception as e:
            conn.rollback()
            print(f"Ошибка при добавлении документа: {e}")
            flash(f"Ошибка при добавлении документа: {str(e)[:100]}", "danger")
            cursor.close()
            return render_template('documents/upload.html')
    
    return render_template('documents/upload.html')

# Редактирование документа
@bp.route('/edit/<int:docid>', methods=['GET', 'POST'])
def edit_document(docid):
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        accesslevel = request.form.get('accesslevel', 'Internal')
        content = request.form.get('content', '').strip()
        
        if not title:
            flash("Введите название документа", "warning")
            cursor.execute("SELECT doctitle, accesslevel, content FROM confidentialdocuments WHERE docid = %s", (docid,))
            doc = cursor.fetchone()
            cursor.close()
            
            if doc:
                return render_template('documents/edit.html', 
                                     docid=docid,
                                     title=doc[0],
                                     accesslevel=doc[1],
                                     content=doc[2] or '')
            else:
                return redirect(url_for('documents.list_documents'))
        
        try:
            # Обновляем документ
            cursor.execute("""
                UPDATE confidentialdocuments 
                SET doctitle = %s, 
                    accesslevel = %s, 
                    content = %s,
                    updateddate = NOW()
                WHERE docid = %s
                RETURNING docid
            """, (title, accesslevel, content, docid))
            
            updated = cursor.fetchone()
            conn.commit()
            
            if updated:
                flash(f"Документ '{title}' успешно обновлен", "success")
            else:
                flash("Документ не найден", "warning")
            
            cursor.close()
            return redirect(url_for('documents.view_document', docid=docid))
            
        except Exception as e:
            conn.rollback()
            print(f"Ошибка при обновлении документа: {e}")
            flash(f"Ошибка при обновлении: {str(e)[:100]}", "danger")
            cursor.close()
            return redirect(url_for('documents.list_documents'))
    
    # GET запрос - показываем форму редактирования
    try:
        cursor.execute("""
            SELECT doctitle, accesslevel, content 
            FROM confidentialdocuments 
            WHERE docid = %s
        """, (docid,))
        
        doc = cursor.fetchone()
        cursor.close()
        
        if not doc:
            flash("Документ не найден", "warning")
            return redirect(url_for('documents.list_documents'))
        
        return render_template('documents/edit.html',
                             docid=docid,
                             title=doc[0],
                             accesslevel=doc[1],
                             content=doc[2] or '')
        
    except Exception as e:
        print(f"Ошибка при получении документа: {e}")
        cursor.close()
        flash("Ошибка при загрузке документа", "danger")
        return redirect(url_for('documents.list_documents'))

# Удаление документа
@bp.route('/delete/<int:docid>', methods=['POST'])
def delete_document(docid):
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Требуется авторизация'}), 401
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        # Получаем название документа для сообщения
        cursor.execute("SELECT doctitle FROM confidentialdocuments WHERE docid = %s", (docid,))
        doc = cursor.fetchone()
        
        if not doc:
            cursor.close()
            return jsonify({'success': False, 'error': 'Документ не найден'}), 404
        
        title = doc[0]
        
        # Пробуем использовать функцию fn_delete_confidential_document
        try:
            cursor.execute("SELECT fn_delete_confidential_document(%s)", (docid,))
        except Exception:
            # Если функция недоступна, удаляем напрямую
            cursor.execute("DELETE FROM confidentialdocuments WHERE docid = %s", (docid,))
        
        conn.commit()
        cursor.close()
        
        return jsonify({
            'success': True,
            'message': f'Документ "{title}" успешно удален'
        })
        
    except Exception as e:
        conn.rollback()
        print(f"Ошибка при удалении документа: {e}")
        cursor.close()
        return jsonify({'success': False, 'error': str(e)[:100]}), 500

# Скачивание документа
@bp.route('/download/<int:docid>')
def download_document(docid):
    if not session.get('logged_in'):
        flash("Требуется авторизация", "danger")
        return redirect(url_for('auth.login'))
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT doctitle, file_data, content_encrypted, content
            FROM confidentialdocuments 
            WHERE docid = %s 
            LIMIT 1
        """, (docid,))
        
        row = cursor.fetchone()
        
        if not row:
            cursor.close()
            flash("Файл не найден", "warning")
            return redirect(url_for('documents.list_documents'))
        
        doctitle, file_data, content_encrypted, content = row
        data_bytes = None
        
        # Определяем источник данных
        if file_data is not None:
            data_bytes = file_data
        elif content_encrypted is not None:
            try:
                cursor.execute("SELECT decrypt_data(%s);", (content_encrypted,))
                result = cursor.fetchone()
                if result and result[0] is not None:
                    data_bytes = result[0]
            except Exception:
                data_bytes = b"[Encrypted content]"
        elif content is not None:
            data_bytes = content.encode('utf-8')
        
        cursor.close()
        
        if data_bytes is None:
            flash("Невозможно получить содержимое файла", "warning")
            return redirect(url_for('documents.list_documents'))
        
        # Создаем файл для скачивания
        filename = f"{doctitle.replace(' ', '_')}.txt"
        
        if isinstance(data_bytes, str):
            data_bytes = data_bytes.encode('utf-8')
        
        return send_file(
            io.BytesIO(data_bytes),
            download_name=filename,
            as_attachment=True,
            mimetype='text/plain'
        )
        
    except Exception as e:
        print(f"Ошибка при скачивании документа: {e}")
        cursor.close()
        flash("Ошибка при скачивании файла", "danger")
        return redirect(url_for('documents.list_documents'))

# API для получения списка документов (JSON)
@bp.route('/api/list')
def api_list():
    if not session.get('logged_in'):
        return jsonify({'error': 'Требуется авторизация'}), 401
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT docid, doctitle, accesslevel, createddate, department_id, creatorid 
            FROM confidentialdocuments 
            ORDER BY createddate DESC
            LIMIT 20
        """)
        
        rows = cursor.fetchall()
        cursor.close()
        
        documents = []
        for row in rows:
            documents.append({
                'id': row[0],
                'title': row[1],
                'access': row[2],
                'created': str(row[3]) if row[3] else None,
                'department': row[4],
                'creator': row[5]
            })
        
        return jsonify({
            'success': True,
            'count': len(documents),
            'documents': documents,
            'user': session.get('login')
        })
        
    except Exception as e:
        print(f"Ошибка API: {e}")
        cursor.close()
        
        # Демо-данные
        return jsonify({
            'success': True,
            'count': 3,
            'documents': [
                {
                    'id': 1,
                    'title': 'Регламент ТО автомобилей',
                    'access': 'Internal',
                    'created': '2024-01-15 10:30:00',
                    'department': 1,
                    'creator': 1
                },
                {
                    'id': 2,
                    'title': 'Договор с поставщиком запчастей',
                    'access': 'Confidential',
                    'created': '2024-01-14 14:20:00',
                    'department': 2,
                    'creator': 2
                },
                {
                    'id': 3,
                    'title': 'Отчет о прибыли за декабрь 2024',
                    'access': 'TopSecret',
                    'created': '2024-01-10 09:15:00',
                    'department': 1,
                    'creator': 3
                }
            ],
            'user': session.get('login'),
            'note': 'Демо-данные (реальная БД недоступна)'
        })