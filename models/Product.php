<?php
class Product {
    private $conn;
    private $table_name = 'products';

    public $id;
    public $seller_id;
    public $name;
    public $description;
    public $price;
    public $color;
    public $material;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function createProduct() {
        $query = "INSERT INTO " . $this->table_name . " 
                  SET seller_id=:seller_id, 
                      name=:name, 
                      description=:description, 
                      price=:price,
                      color=:color,
                      material=:material";
        
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(":seller_id", $this->seller_id);
        $stmt->bindParam(":name", $this->name);
        $stmt->bindParam(":description", $this->description);
        $stmt->bindParam(":price", $this->price);
        $stmt->bindParam(":color", $this->color);
        $stmt->bindParam(":material", $this->material);

        if($stmt->execute()) {
            $this->id = $this->conn->lastInsertId();
            return true;
        }

        return false;
    }

    public function getProductsBySeller($seller_id) {
        $query = "SELECT * FROM " . $this->table_name . "
                  WHERE seller_id = :seller_id
                  ORDER BY name";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":seller_id", $seller_id);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateProduct() {
        $query = "UPDATE " . $this->table_name . "
                  SET name=:name, 
                      description=:description, 
                      price=:price,
                      color=:color,
                      material=:material
                  WHERE id = :id AND seller_id = :seller_id";
        
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(":name", $this->name);
        $stmt->bindParam(":description", $this->description);
        $stmt->bindParam(":price", $this->price);
        $stmt->bindParam(":color", $this->color);
        $stmt->bindParam(":material", $this->material);
        $stmt->bindParam(":id", $this->id);
        $stmt->bindParam(":seller_id", $this->seller_id);

        return $stmt->execute();
    }

    public function deleteProduct() {
        $query = "DELETE FROM " . $this->table_name . "
                  WHERE id = :id AND seller_id = :seller_id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $this->id);
        $stmt->bindParam(":seller_id", $this->seller_id);

        return $stmt->execute();
    }

    public function getProductDetails() {
        $query = "SELECT p.*, u.full_name as seller_name 
                  FROM " . $this->table_name . " p
                  JOIN users u ON p.seller_id = u.id
                  WHERE p.id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $this->id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function searchProducts($keyword) {
        $query = "SELECT p.*, u.full_name as seller_name 
                  FROM " . $this->table_name . " p
                  JOIN users u ON p.seller_id = u.id
                  WHERE p.name LIKE :keyword 
                  OR p.description LIKE :keyword 
                  OR p.color LIKE :keyword";
        
        $stmt = $this->conn->prepare($query);
        $keyword = "%{$keyword}%";
        $stmt->bindParam(":keyword", $keyword);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getRecentProducts($limit = 10) {
        $query = "SELECT p.*, u.full_name as seller_name 
                  FROM " . $this->table_name . " p
                  JOIN users u ON p.seller_id = u.id
                  ORDER BY p.id DESC
                  LIMIT :limit";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getProductAnalytics($seller_id) {
        $query = "SELECT 
                    COUNT(*) as total_products,
                    AVG(price) as average_price,
                    MAX(price) as max_price,
                    MIN(price) as min_price,
                    COUNT(DISTINCT color) as unique_colors,
                    COUNT(DISTINCT material) as unique_materials
                  FROM " . $this->table_name . "
                  WHERE seller_id = :seller_id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":seller_id", $seller_id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}