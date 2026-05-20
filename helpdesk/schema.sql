CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    role ENUM('user', 'technician', 'admin') DEFAULT 'user',
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT NOW()
);

CREATE TABLE tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    status ENUM('open', 'in_progress', 'resolved', 'closed') DEFAULT 'open',
    priority ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    category ENUM('hardware', 'software', 'network', 'security_incident') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NULL,
    escalated BOOLEAN DEFAULT FALSE,
    requester_id INT NOT NULL,
    assignee_id INT NULL,
    created_at DATETIME DEFAULT NOW(),
    updated_at DATETIME DEFAULT NOW() ON UPDATE NOW(),
    resolved_at DATETIME NULL,
    FOREIGN KEY (requester_id) REFERENCES users(id),
    FOREIGN KEY (assignee_id) REFERENCES users(id)
);

CREATE TABLE activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    actor_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    old_value VARCHAR(100) NULL,
    new_value VARCHAR(100) NULL,
    note TEXT NULL,
    created_at DATETIME DEFAULT NOW(),
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);