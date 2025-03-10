<?php
class SecurityConfig
{
       private static $secret_key = 'YOUR_VERY_SECRET_AND_LONG_KEY_HERE';

       public static function hashPassword($password)
       {
              return password_hash($password, PASSWORD_ARGON2ID, [
                     'memory_cost' => 1024 * 16,
                     'time_cost' => 3,
                     'threads' => 2
              ]);
       }

       public static function verifyPassword($input, $hashed)
       {
              return password_verify($input, $hashed);
       }

       public static function generateSecureToken($length = 32)
       {
              return bin2hex(random_bytes($length));
       }

       public static function sanitizeInput($input)
       {
              return htmlspecialchars(strip_tags(trim($input)));
       }

       public static function generateJWT($payload)
       {
              $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
              $payload = base64_encode(json_encode($payload));
              $signature = hash_hmac('sha256', "$header.$payload", self::$secret_key, true);
              $signature = base64_encode($signature);

              return "$header.$payload.$signature";
       }

       public static function verifyJWT($token)
       {
              $parts = explode('.', $token);
              if (count($parts) !== 3) return false;

              list($header, $payload, $signature) = $parts;

              $valid_signature = hash_hmac('sha256', "$header.$payload", self::$secret_key, true);
              $valid_signature = base64_encode($valid_signature);

              if ($signature !== $valid_signature) return false;

              $payload_decoded = json_decode(base64_decode($payload), true);

              // Check token expiration
              if (isset($payload_decoded['exp']) && $payload_decoded['exp'] < time()) {
                     return false;
              }

              return $payload_decoded;
       }
}
