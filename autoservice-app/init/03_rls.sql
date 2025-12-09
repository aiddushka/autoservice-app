ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Простая политика: пользователь видит только свои документы
CREATE POLICY user_docs ON documents
    FOR SELECT USING (owner_id = current_user_id());
