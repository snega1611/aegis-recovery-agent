CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    status VARCHAR(50) NOT NULL
);

INSERT INTO orders (status)
VALUES
    ('processing'),
    ('shipped')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(100) PRIMARY KEY,
    alert_name VARCHAR(100) NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP NOT NULL,
    description TEXT
);