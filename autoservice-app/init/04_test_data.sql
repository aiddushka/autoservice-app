INSERT INTO users (username, role) VALUES
('admin', 'admin'),
('user1', 'user'),
('user2', 'user');

INSERT INTO documents (title, content, owner_id) VALUES
('Doc 1', 'Secret content', 1),
('Doc 2', 'User1 private', 2),
('Doc 3', 'User2 notes', 3);
