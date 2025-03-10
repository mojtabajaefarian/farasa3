<?php
class User
{
    private $conn;
    private $table_name = 'users';

    public $id;
    public $username;
    public $email;
    public $password;
    public $user_type;
    public $full_name;
    public $phone_number;

    public function __construct($db)
    {
        $this->conn = $db;
    }

    public function register()
    {
        $query = "INSERT INTO " . $this->table_name . " 
                  SET username=:username, 
                      email=:email, 
                      password=:password, 
                      user_type=:user_type, 
                      full_name=:full_name, 
                      phone_number=:phone_number";

        $stmt = $this->conn->prepare($query);

        $this->password = password_hash($this->password, PASSWORD_BCRYPT);

        $stmt->bindParam(":username", $this->username);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":password", $this->password);
        $stmt->bindParam(":user_type", $this->user_type);
        $stmt->bindParam(":full_name", $this->full_name);
        $stmt->bindParam(":phone_number", $this->phone_number);

        if ($stmt->execute()) {
            return true;
        }

        return false;
    }

    public function login()
    {
        $query = "SELECT * FROM " . $this->table_name . " 
                  WHERE username = :username LIMIT 1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $this->username);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row && password_verify($this->password, $row['password'])) {
            $this->id = $row['id'];
            $this->user_type = $row['user_type'];
            return true;
        }

        return false;
    }

    public function getUserProfile()
    {
        $query = "SELECT * FROM " . $this->table_name . " 
                  WHERE id = :id LIMIT 1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $this->id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updateProfile()
    {
        $query = "UPDATE " . $this->table_name . "
                  SET full_name = :full_name, 
                      email = :email, 
                      phone_number = :phone_number
                  WHERE id = :id";

        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(":full_name", $this->full_name);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":phone_number", $this->phone_number);
        $stmt->bindParam(":id", $this->id);

        if ($stmt->execute()) {
            return true;
        }

        return false;
    }

    public function changePassword()
    {
        $query = "UPDATE " . $this->table_name . "
                  SET password = :password
                  WHERE id = :id";

        $stmt = $this->conn->prepare($query);

        $hashedPassword = password_hash($this->password, PASSWORD_BCRYPT);
        $stmt->bindParam(":password", $hashedPassword);
        $stmt->bindParam(":id", $this->id);

        if ($stmt->execute()) {
            return true;
        }

        return false;
    }
    public function checkPasswordResetToken($reset_token)
    {
        $query = "SELECT * FROM password_resets WHERE token = :token AND expiry > NOW()";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':token', $reset_token);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }

    public function generatePasswordResetToken($reset_token, $token_expiry)
    {
        $query = "UPDATE users SET reset_token = :reset_token, token_expiry = :token_expiry WHERE email = :email";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':reset_token', $reset_token);
        $stmt->bindParam(':token_expiry', $token_expiry);
        $stmt->bindParam(':email', $this->email);

        return $stmt->execute();
    }
    public function verifyCurrentPassword($current_password)
    {
        $query = "SELECT password FROM " . $this->table_name . " WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':id', $this->id);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (password_verify($current_password, $row['password'])) {
            return true;
        } else {
            return false;
        }
    }
}
