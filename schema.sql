-- Create Database (Run this manually if needed, or rely on app)
CREATE DATABASE IF NOT EXISTS ehealth_db;
USE ehealth_db;

-- Users Table (Subjects)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    phone_number VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL, -- Storing Bcrypt Hash
    role ENUM('doctor', 'patient', 'admin') NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    otp_code VARCHAR(6),
    otp_expires_at TIMESTAMP NULL,
    public_key TEXT, -- For Digital SignaturesVerification
    private_key TEXT, -- Encrypted Private Key (Simulated storage for demo)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Medical Records Table (Objects)
CREATE TABLE IF NOT EXISTS records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    diagnosis TEXT NOT NULL, -- Will be Encrypted
    prescription TEXT NOT NULL, -- Will be Encrypted
    digital_signature TEXT, -- Simulation of signature
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES users(id),
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);

-- Audit Logs (for Security Dashboard)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255) NOT NULL, -- e.g., "LOGIN_SUCCESS", "ACCESS_DENIED", "VIEW_RECORD"
    details TEXT,
    ip_address VARCHAR(45),
    prev_hash VARCHAR(255), -- Hash of the previous log entry
    hash VARCHAR(255), -- Hash of this entry (including prev_hash)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Dummy Data
-- All passwords are 'password123' (hashed with bcrypt for demo)
-- Hash: $2b$10$YourGeneratedHashHere (We will generate real ones in seed script, checking for now)

INSERT INTO users (username, email, password_hash, role, full_name) VALUES 
('dr_strange', 'dr.strange@example.com', '$2b$10$CwTycUXWue0Thq9StjUM0u.tXp0y.lWkXo.xZqO1.yWkXo.xZqO1', 'doctor', 'Dr. Stephen Strange'),
('tony_stark', 'tony.stark@example.com', '$2b$10$CwTycUXWue0Thq9StjUM0u.tXp0y.lWkXo.xZqO1.yWkXo.xZqO1', 'patient', 'Tony Stark'),
('fury_admin', 'nick.fury@example.com', '$2b$10$CwTycUXWue0Thq9StjUM0u.tXp0y.lWkXo.xZqO1.yWkXo.xZqO1', 'admin', 'Nick Fury');
-- Note: You'll need to generate a real hash for 'password123' to make login work. 
-- I will add a seeder script to fix this.
