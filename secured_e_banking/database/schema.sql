CREATE DATABASE e_banking;

USE e_banking;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,  -- Removed UNIQUE constraint
    account_number VARCHAR(20) NOT NULL UNIQUE,  -- Account number remains unique
    password_hash VARCHAR(255) NOT NULL,
    encrypted_balance BLOB  -- Store encrypted balance as BLOB
);

CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    amount BLOB,  -- Store encrypted amount as BLOB
    transaction_date DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);