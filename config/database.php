<?php
class Database
{
       private $host = 'localhost';
       private $db_name = 'product_management';
       private $username = 'root';
       private $password = '';
       public $conn;

       public function getConnection()
       {
              $this->conn = null;

              try {
                     $this->conn = new PDO(
                            "mysql:host=" . $this->host . ";dbname=" . $this->db_name,
                            $this->username,
                            $this->password
                     );
                     $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
              } catch (PDOException $exception) {
                     error_log("Database Connection Error: " . $exception->getMessage());
                     throw new Exception("Database connection failed");
              }

              return $this->conn;
       }
}
