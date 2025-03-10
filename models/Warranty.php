<?php
class Warranty {
    private $conn;
    private $table_name = 'warranty_requests';

    public $id;
    public $seller_id;
    public $customer_id;
    public $product_id;
    public $sale_date;
    public $warranty_period;
    public $quantity;
    public $status;
    public $customer_phone;
    public $description;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function createWarrantyRequest() {
        $query = "INSERT INTO " . $this->table_name . " 
                  SET seller_id=:seller_id, 
                      customer_id=:customer_id, 
                      product_id=:product_id, 
                      sale_date=:sale_date,
                      warranty_period=:warranty_period,
                      quantity=:quantity,
                      status='pending',
                      customer_phone=:customer_phone,
                      description=:description";
        
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(":seller_id", $this->seller_id);
        $stmt->bindParam(":customer_id", $this->customer_id);
        $stmt->bindParam(":product_id", $this->product_id);
        $stmt->bindParam(":sale_date", $this->sale_date);
        $stmt->bindParam(":warranty_period", $this->warranty_period);
        $stmt->bindParam(":quantity", $this->quantity);
        $stmt->bindParam(":customer_phone", $this->customer_phone);
        $stmt->bindParam(":description", $this->description);

        if($stmt->execute()) {
            $this->id = $this->conn->lastInsertId();
            return true;
        }

        return false;
    }

    public function getWarrantyRequestsBySeller($seller_id) {
        $query = "SELECT wr.*, p.name as product_name, u.full_name as customer_name 
                  FROM " . $this->table_name . " wr
                  JOIN products p ON wr.product_id = p.id
                  JOIN users u ON wr.customer_id = u.id
                  WHERE wr.seller_id = :seller_id
                  ORDER BY wr.created_at DESC";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":seller_id", $seller_id);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getWarrantyRequestsByCustomer($customer_id) {
        $query = "SELECT wr.*, p.name as product_name, u.full_name as seller_name 
                  FROM " . $this->table_name . " wr
                  JOIN products p ON wr.product_id = p.id
                  JOIN users u ON wr.seller_id = u.id
                  WHERE wr.customer_id = :customer_id
                  ORDER BY wr.created_at DESC";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":customer_id", $customer_id);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateWarrantyRequest() {
        $query = "UPDATE " . $this->table_name . "
                  SET product_id=:product_id, 
                      sale_date=:sale_date,
                      warranty_period=:warranty_period,
                      quantity=:quantity,
                      customer_phone=:customer_phone,
                      description=:description
                  WHERE id = :id AND status = 'pending'";
        
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(":product_id", $this->product_id);
        $stmt->bindParam(":sale_date", $this->sale_date);
        $stmt->bindParam(":warranty_period", $this->warranty_period);
        $stmt->bindParam(":quantity", $this->quantity);
        $stmt->bindParam(":customer_phone", $this->customer_phone);
        $stmt->bindParam(":description", $this->description);
        $stmt->bindParam(":id", $this->id);

        return $stmt->execute();
    }

    public function changeWarrantyStatus($new_status) {
        $query = "UPDATE " . $this->table_name . "
                  SET status = :status
                  WHERE id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":status", $new_status);
        $stmt->bindParam(":id", $this->id);

        return $stmt->execute();
    }

    public function deleteWarrantyRequest() {
        $query = "DELETE FROM " . $this->table_name . "
                  WHERE id = :id AND status = 'pending'";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $this->id);

        return $stmt->execute();
    }

    public function generateAdminReport($start_date, $end_date) {
        $query = "SELECT 
                    COUNT(*) as total_warranties,
                    SUM(p.price * wr.quantity) as total_value,
                    AVG(warranty_period) as avg_warranty_period,
                    status,
                    COUNT(DISTINCT seller_id) as unique_sellers
                  FROM " . $this->table_name . " wr
                  JOIN products p ON wr.product_id = p.id
                  WHERE wr.created_at BETWEEN :start_date AND :end_date
                  GROUP BY status";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":start_date", $start_date);
        $stmt->bindParam(":end_date", $end_date);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function checkWarrantyValidity() {
        $query = "SELECT 
                    id, 
                    sale_date, 
                    warranty_period, 
                    DATEDIFF(CURRENT_DATE, sale_date) as days_since_sale,
                    warranty_period * 30 as warranty_days
                  FROM " . $this->table_name . "
                  WHERE id = :id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $this->id);
        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result['days_since_sale'] <= $result['warranty_days']) {
            return true;
        }

        return false;
    }
	public function createWarrantyInteraction($user_id, $message, $attachment_path = null) {
        $query = "INSERT INTO warranty_interactions 
                  (warranty_id, user_id, message, attachment_path) 
                  VALUES (:warranty_id, :user_id, :message, :attachment_path)";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":warranty_id", $this->id);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":attachment_path", $attachment_path);

        return $stmt->execute();
    }

    public function getWarrantyInteractions() {
        $query = "SELECT wi.*, u.full_name, u.user_type 
                  FROM warranty_interactions wi
                  JOIN users u ON wi.user_id = u.id
                  WHERE wi.warranty_id = :warranty_id
                  ORDER BY wi.created_at ASC";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":warranty_id", $this->id);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}