-- Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    user_type ENUM('admin', 'seller', 'customer') NOT NULL,
    full_name VARCHAR(100),
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products Table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    seller_id INT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    color VARCHAR(50),
    material VARCHAR(50),
    FOREIGN KEY (seller_id) REFERENCES users(id)
);

-- Warranty Requests Table
CREATE TABLE warranty_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    seller_id INT,
    customer_id INT,
    product_id INT,
    sale_date DATE,
    warranty_period INT,
    quantity INT,
    status ENUM('pending', 'approved', 'rejected', 'complaint') DEFAULT 'pending',
    customer_phone VARCHAR(20),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id),
    FOREIGN KEY (customer_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Warranty Interaction Log
CREATE TABLE warranty_interactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    warranty_id INT,
    user_id INT,
    message TEXT,
    attachment_path VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (warranty_id) REFERENCES warranty_requests(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);