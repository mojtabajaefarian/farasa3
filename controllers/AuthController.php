<?php
require_once '../config/database.php';
require_once '../models/User.php';

class AuthController
{
    private $db;
    private $user;

    public function __construct()
    {
        $database = new Database();
        $this->db = $database->getConnection();
        $this->user = new User($this->db);
    }

    public function register($username, $email, $password, $user_type, $full_name, $phone_number)
    {
        $this->user->username = $username;
        $this->user->email = $email;
        $this->user->password = $password;
        $this->user->user_type = $user_type;
        $this->user->full_name = $full_name;
        $this->user->phone_number = $phone_number;

        if ($this->user->register()) {
            return [
                'status' => 'success',
                'message' => 'User registered successfully',
                'user' => [
                    'username' => $username,
                    'email' => $email,
                    'user_type' => $user_type
                ]
            ];
        } else {
            return [
                'status' => 'error',
                'message' => 'Registration failed'
            ];
        }
    }

    public function login($username, $password)
    {
        $this->user->username = $username;
        $this->user->password = $password;

        if ($this->user->login()) {
            $userProfile = $this->user->getUserProfile();

            return [
                'status' => 'success',
                'message' => 'Login successful',
                'user' => [
                    'id' => $userProfile['id'],
                    'username' => $userProfile['username'],
                    'email' => $userProfile['email'],
                    'user_type' => $userProfile['user_type'],
                    'full_name' => $userProfile['full_name']
                ],
                'token' => $this->generateJWT($userProfile)
            ];
        } else {
            return [
                'status' => 'error',
                'message' => 'Invalid credentials'
            ];
        }
    }

    private function generateJWT($userProfile)
    {
        $secretKey = 'YOUR_SECRET_KEY_HERE';
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600; // Valid for 1 hour

        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'user_id' => $userProfile['id'],
            'username' => $userProfile['username'],
            'user_type' => $userProfile['user_type']
        ];

        return $this->encodeJWT($payload, $secretKey);
    }

    private function encodeJWT($payload, $secretKey)
    {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($payload)));

        $signature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", $secretKey, true);
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return "$base64UrlHeader.$base64UrlPayload.$base64UrlSignature";
    }

    public function verifyJWT($token)
    {
        $secretKey = 'YOUR_SECRET_KEY_HERE';
        $tokenParts = explode('.', $token);

        if (count($tokenParts) !== 3) {
            return false;
        }

        list($header, $payload, $signature) = $tokenParts;

        $validSignature = hash_hmac('sha256', "$header.$payload", $secretKey, true);
        $base64UrlValidSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($validSignature));

        if ($base64UrlValidSignature !== $signature) {
            return false;
        }

        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);

        if ($payload['exp'] < time()) {
            return false;
        }

        return $payload;
    }

    public function updateProfile($user_id, $full_name, $email, $phone_number)
    {
        $this->user->id = $user_id;
        $this->user->full_name = $full_name;
        $this->user->email = $email;
        $this->user->phone_number = $phone_number;

        if ($this->user->updateProfile()) {
            return [
                'status' => 'success',
                'message' => 'Profile updated successfully',
                'user' => [
                    'full_name' => $full_name,
                    'email' => $email,
                    'phone_number' => $phone_number
                ]
            ];
        } else {
            return [
                'status' => 'error',
                'message' => 'Profile update failed'
            ];
        }
    }

    public function changePassword($user_id, $current_password, $new_password)
    {
        $this->user->id = $user_id;
        $this->user->password = $new_password;

        // First, verify current password
        if (!$this->user->verifyCurrentPassword($current_password)) {
            return [
                'status' => 'error',
                'message' => 'Current password is incorrect'
            ];
        }

        // Validate new password strength
        if (!$this->validatePasswordStrength($new_password)) {
            return [
                'status' => 'error',
                'message' => 'New password does not meet strength requirements'
            ];
        }

        if ($this->user->changePassword()) {
            return [
                'status' => 'success',
                'message' => 'Password changed successfully'
            ];
        } else {
            return [
                'status' => 'error',
                'message' => 'Password change failed'
            ];
        }
    }

    private function validatePasswordStrength($password)
    {
        // Password requirements:
        // - At least 8 characters long
        // - Contains at least one uppercase letter
        // - Contains at least one lowercase letter
        // - Contains at least one number
        // - Contains at least one special character
        $requirements = [
            'length' => strlen($password) >= 8,
            'uppercase' => preg_match('/[A-Z]/', $password),
            'lowercase' => preg_match('/[a-z]/', $password),
            'number' => preg_match('/[0-9]/', $password),
            'special' => preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)
        ];

        return !in_array(false, $requirements);
    }

    public function resetPassword($email)
    {
        // Generate a unique reset token
        $reset_token = bin2hex(random_bytes(32));
        $token_expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

        $this->user->email = $email;

        if ($this->user->generatePasswordResetToken($reset_token, $token_expiry)) {
            // Send reset email
            $this->sendPasswordResetEmail($email, $reset_token);

            return [
                'status' => 'success',
                'message' => 'Password reset link sent to your email'
            ];
        } else {
            return [
                'status' => 'error',
                'message' => 'Failed to generate password reset token'
            ];
        }
    }

    private function sendPasswordResetEmail($email, $reset_token)
    {
        $reset_link = "https://yourdomain.com/reset-password?token=" . $reset_token;

        $subject = "Password Reset Request";
        $message = "Click the following link to reset your password:\n\n" . $reset_link;
        $headers = "From: noreply@yourdomain.com";

        // Send email (implement your preferred email sending method)
        mail($email, $subject, $message, $headers);
    }

    public function validatePasswordResetToken($reset_token)
    {
        return $this->user->checkPasswordResetToken($reset_token);
    }
}
