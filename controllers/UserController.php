<?php
class UserController {
    private $db;
    private $logger;
    private $requestLimiter;

    public function __construct() {
        $this->db = Database::getInstance();
        $this->logger = new Logger();
        $this->requestLimiter = new RequestLimiter();
    }

    // احراز هویت پیشرفته
    public function authenticate($username, $password) {
        // محدودیت تعداد تلاش‌های ورود
        if (!$this->requestLimiter->checkLoginAttempts($username)) {
            return [
                'status' => false,
                'message' => 'تعداد تلاش‌های ورود بیش از حد مجاز است'
            ];
        }

        $stmt = $this->db->prepare("
            SELECT id, username, password, user_type, status 
            FROM users 
            WHERE username = :username
        ");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // بررسی وضعیت حساب کاربری
            if ($user['status'] !== 'active') {
                return [
                    'status' => false,
                    'message' => 'حساب کاربری شما غیرفعال است'
                ];
            }

            // ایجاد سشن امن
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['user_type'] = $user['user_type'];
            $_SESSION['token'] = bin2hex(random_bytes(32));

            // ثبت لاگ ورود
            $this->logger->log('login', [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'ip_address' => $_SERVER['REMOTE_ADDR']
            ]);

            // ریست کردن تعداد تلاش‌های ناموفق
            $this->requestLimiter->resetLoginAttempts($username);

            return [
                'status' => true,
                'message' => 'ورود موفقیت‌آمیز',
                'user_type' => $user['user_type']
            ];
        } else {
            // ثبت تلاش ناموفق
            $this->requestLimiter->incrementLoginAttempts($username);
            
            $this->logger->log('login_failed', [
                'username' => $username,
                'ip_address' => $_SERVER['REMOTE_ADDR']
            ]);

            return [
                'status' => false,
                'message' => 'نام کاربری یا رمز عبور اشتباه است'
            ];
        }
    }

    // ثبت نام با اعتبارسنجی پیشرفته
    public function register($data) {
        // اعتبارسنجی داده‌ها
        $validationErrors = $this->validateRegistrationData($data);
        if (!empty($validationErrors)) {
            return [
                'status' => false,
                'errors' => $validationErrors
            ];
        }

        // هش کردن رمز عبور
        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 12]);

// آماده‌سازی کوئری ثبت نام
$stmt = $this->db->prepare("
INSERT INTO users 
(username, email, password, mobile, user_type, status, created_at) 
VALUES (:username, :email, :password, :mobile, :user_type, 'pending', NOW())
");

try {
$result = $stmt->execute([
    ':username' => $data['username'],
    ':email' => $data['email'],
    ':password' => $hashedPassword,
    ':mobile' => $data['mobile'],
    ':user_type' => $data['user_type']
]);

if ($result) {
    $userId = $this->db->lastInsertId();

    // ارسال ایمیل تأیید
    $this->sendVerificationEmail($data['email'], $userId);

    // ثبت لاگ
    $this->logger->log('user_registration', [
        'user_id' => $userId,
        'username' => $data['username'],
        'email' => $data['email']
    ]);

    return [
        'status' => true,
        'message' => 'ثبت نام با موفقیت انجام شد. لطفاً ایمیل خود را تأیید کنید.',
        'user_id' => $userId
    ];
}
} catch (PDOException $e) {
// مدیریت خطاهای احتمالی
$this->logger->log('registration_error', [
    'error' => $e->getMessage(),
    'data' => $data
]);

return [
    'status' => false,
    'message' => 'خطا در ثبت نام. لطفاً مجدداً تلاش کنید.',
    'error' => $e->getMessage()
];
}
}

// اعتبارسنجی داده‌های ثبت نام
private function validateRegistrationData($data) {
$errors = [];

// بررسی نام کاربری
if (empty($data['username']) || strlen($data['username']) < 3) {
$errors[] = 'نام کاربری نامعتبر است';
}

// بررسی تکراری نبودن نام کاربری
$stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
$stmt->execute([':username' => $data['username']]);
if ($stmt->fetchColumn() > 0) {
$errors[] = 'نام کاربری قبلاً استفاده شده است';
}

// بررسی ایمیل
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
$errors[] = 'ایمیل نامعتبر است';
}

// بررسی تکراری نبودن ایمیل
$stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
$stmt->execute([':email' => $data['email']]);
if ($stmt->fetchColumn() > 0) {
$errors[] = 'ایمیل قبلاً ثبت شده است';
}

// بررسی رمز عبور
if (empty($data['password']) || 
strlen($data['password']) < 8 || 
!preg_match("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/", $data['password'])
) {
$errors[] = 'رمز عبور باید حداقل 8 کاراکتر و شامل حروف بزرگ، کوچک و اعداد باشد';
}
// بررسی شماره موبایل
if (empty($data['mobile']) || !preg_match('/^09\d{9}$/', $data['mobile'])) {
       $errors[] = 'شماره موبایل نامعتبر است';
   }

   // بررسی نوع کاربری
   $validUserTypes = ['admin', 'seller', 'customer'];
   if (empty($data['user_type']) || !in_array($data['user_type'], $validUserTypes)) {
       $errors[] = 'نوع کاربری نامعتبر است';
   }

   return $errors;
}

// بازیابی رمز عبور
public function resetPassword($email) {
   // تولید توکن بازیابی
   $resetToken = bin2hex(random_bytes(32));
   $expiryTime = date('Y-m-d H:i:s', strtotime('+1 hour'));

   try {
       // ذخیره توکن در دیتابیس
       $stmt = $this->db->prepare("
           UPDATE users 
           SET reset_token = :token, 
               reset_token_expiry = :expiry 
           WHERE email = :email
       ");
       $stmt->execute([
           ':token' => $resetToken,
           ':expiry' => $expiryTime,
           ':email' => $email
       ]);

       // ارسال ایمیل بازیابی
       $this->sendPasswordResetEmail($email, $resetToken);

       // ثبت لاگ
       $this->logger->log('password_reset_request', [
           'email' => $email,
           'token' => $resetToken
       ]);

       return [
           'status' => true,
           'message' => 'لینک بازیابی رمز عبور به ایمیل شما ارسال شد'
       ];
   } catch (Exception $e) {
       // مدیریت خطا
       $this->logger->log('password_reset_error', [
           'email' => $email,
           'error' => $e->getMessage()
       ]);

       return [
           'status' => false,
           'message' => 'خطا در بازیابی رمز عبور'
       ];
   }
}

// تغییر رمز عبور
public function changePassword($userId, $oldPassword, $newPassword) {
   try {
       // بررسی رمز عبور فعلی
       $stmt = $this->db->prepare("SELECT password FROM users WHERE id = :user_id");
       $stmt->execute([':user_id' => $userId]);
       $currentPasswordHash = $stmt->fetchColumn();

       if (!password_verify($oldPassword, $currentPasswordHash)) {
           return [
               'status' => false,
               'message' => 'رمز عبور فعلی اشتباه است'
           ];
       }

       // اعتبارسنجی رمز عبور جدید
       $passwordValidationErrors = $this->validatePassword($newPassword);
       if (!empty($passwordValidationErrors)) {
           return [
               'status' => false,
               'errors' => $passwordValidationErrors
           ];
       }

       // هش کردن رمز عبور جدید
       $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);

       // بروزرسانی رمز عبور
       $updateStmt = $this->db->prepare("
           UPDATE users 
           SET password = :new_password, 
               updated_at = NOW() 
           WHERE id = :user_id
       ");
       $updateStmt->execute([
           ':new_password' => $newPasswordHash,
           ':user_id' => $userId
       ]);

// ثبت لاگ تغییر رمز عبور
$this->logger->log('password_change', [
       'user_id' => $userId,
       'ip_address' => $_SERVER['REMOTE_ADDR']
   ]);

   // اینوالیدیت کردن سشن‌های دیگر
   $this->invalidateOtherSessions($userId);

   return [
       'status' => true,
       'message' => 'رمز عبور با موفقیت تغییر یافت'
   ];
} catch (Exception $e) {
   // مدیریت خطا
   $this->logger->log('password_change_error', [
       'user_id' => $userId,
       'error' => $e->getMessage()
   ]);

   return [
       'status' => false,
       'message' => 'خطا در تغییر رمز عبور'
   ];
}
}

// اعتبارسنجی رمز عبور
private function validatePassword($password) {
$errors = [];

if (empty($password)) {
   $errors[] = 'رمز عبور نمی‌تواند خالی باشد';
}

if (strlen($password) < 8) {
   $errors[] = 'رمز عبور باید حداقل 8 کاراکتر باشد';
}

if (!preg_match("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/", $password)) {
   $errors[] = 'رمز عبور باید شامل حروف بزرگ، کوچک، اعداد و کاراکترهای خاص باشد';
}

return $errors;
}

// اینوالیدیت کردن سشن‌های دیگر
private function invalidateOtherSessions($userId) {
try {
   // حذف توکن‌های دیگر
   $stmt = $this->db->prepare("
       UPDATE user_sessions 
       SET is_active = 0 
       WHERE user_id = :user_id AND session_id != :current_session
   ");
   $stmt->execute([
       ':user_id' => $userId,
       ':current_session' => session_id()
   ]);
} catch (Exception $e) {
   $this->logger->log('session_invalidation_error', [
       'user_id' => $userId,
       'error' => $e->getMessage()
   ]);
}
}

// دریافت اطلاعات کاربر
public function getUserProfile($userId) {
try {
   $stmt = $this->db->prepare("
       SELECT 
           id, username, email, mobile, 
           user_type, status, created_at, 
           last_login, profile_picture 
       FROM users 
       WHERE id = :user_id
   ");
   $stmt->execute([':user_id' => $userId]);
   $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);

   if ($userProfile) {
       // حذف فیلدهای حساس
       unset($userProfile['password']);
       return [
           'status' => true,
           'data' => $userProfile
       ];
   } else {
       return [
           'status' => false,
           'message' => 'کاربر یافت نشد'
       ];
   }
} catch (Exception $e) {
   $this->logger->log('profile_fetch_error', [
       'user_id' => $userId,
       'error' => $e->getMessage()
   ]);
   return [
       'status' => false,
       'message' => 'خطا در دریافت اطلاعات کاربری'
   ];
}
}

// بروزرسانی پروفایل
public function updateProfile($userId, $data) {
// اعتبارسنجی داده‌های ورودی
$validationErrors = $this->validateProfileUpdateData($data);
if (!empty($validationErrors)) {
   return [
       'status' => false,
       'errors' => $validationErrors
   ];
}

try {
   // آماده‌سازی کوئری بروزرسانی
   $updateFields = [];
   $params = [':user_id' => $userId];

   // بررسی و اضافه کردن فیلدهای قابل بروزرسانی
   $allowedFields = ['email', 'mobile', 'profile_picture', 'full_name'];
   foreach ($allowedFields as $field) {
       if (isset($data[$field])) {
           $updateFields[] = "$field = :$field";
           $params[":$field"] = $data[$field];
       }
   }

   // اگر فیلدی برای بروزرسانی وجود ندارد
   if (empty($updateFields)) {
       return [
           'status' => false,
           'message' => 'هیچ داده‌ای برای بروزرسانی وجود ندارد'
       ];
   }

   // ساخت کوئری پویا
   $query = "UPDATE users SET " . implode(', ', $updateFields) . ", updated_at = NOW() WHERE id = :user_id";
   
   $stmt = $this->db->prepare($query);
   $result = $stmt->execute($params);

   if ($result) {
       // ثبت لاگ بروزرسانی
       $this->logger->log('profile_update', [
           'user_id' => $userId,
           'updated_fields' => array_keys($params)
       ]);

       return [
           'status' => true,
           'message' => 'پروفایل با موفقیت بروزرسانی شد'
       ];
   } else {
       return [
           'status' => false,
           'message' => 'خطا در بروزرسانی پروفایل'
       ];
   }
} catch (Exception $e) {
   // مدیریت خطا
   $this->logger->log('profile_update_error', [
       'user_id' => $userId,
       'error' => $e->getMessage(),
       'data' => $data
   ]);

   return [
       'status' => false,
       'message' => 'خطای سیستمی در بروزرسانی پروفایل'
   ];
}
}

// اعتبارسنجی داده‌های بروزرسانی پروفایل
private function validateProfileUpdateData($data) {
$errors = [];

// اعتبارسنجی ایمیل
if (isset($data['email']) && !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
   $errors[] = 'ایمیل نامعتبر است';
}

// اعتبارسنجی موبایل
if (isset($data['mobile']) && !preg_match('/^09\d{9}$/', $data['mobile'])) {
   $errors[] = 'شماره موبایل نامعتبر است';
}

// بررسی حداکثر طول نام کامل
if (isset($data['full_name']) && strlen($data['full_name']) > 50) {
       $errors[] = 'نام کامل نباید بیش از 50 کاراکتر باشد';
   }

   // بررسی فایل تصویر پروفایل
   if (isset($data['profile_picture'])) {
       $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
       $maxFileSize = 5 * 1024 * 1024; // 5 مگابایت

       if (!in_array($data['profile_picture']['type'], $allowedTypes)) {
           $errors[] = 'فرمت تصویر مجاز نیست';
       }

       if ($data['profile_picture']['size'] > $maxFileSize) {
           $errors[] = 'حجم تصویر نباید بیشتر از 5 مگابایت باشد';
       }
   }

   return $errors;
}

// آپلود تصویر پروفایل
private function uploadProfilePicture($userId, $file) {
   $uploadDir = 'uploads/profile_pictures/';
   
   // ایجاد پوشه آپلود در صورت عدم وجود
   if (!file_exists($uploadDir)) {
       mkdir($uploadDir, 0755, true);
   }

   // نام فایل منحصر به فرد
   $fileName = $userId . '_' . uniqid() . '.' . pathinfo($file['name'], PATHINFO_EXTENSION);
   $uploadPath = $uploadDir . $fileName;

   // کاهش سایز و کیفیت تصویر
   try {
       $image = new Imagick($file['tmp_name']);
       $image->resizeImage(500, 500, Imagick::FILTER_LANCZOS, 1, true);
       $image->setImageCompression(Imagick::COMPRESSION_JPEG);
       $image->setImageCompressionQuality(85);
       $image->writeImage($uploadPath);

       // بروزرسانی مسیر تصویر در دیتابیس
       $stmt = $this->db->prepare("
           UPDATE users 
           SET profile_picture = :profile_path 
           WHERE id = :user_id
       ");
       $stmt->execute([
           ':profile_path' => $uploadPath,
           ':user_id' => $userId
       ]);

       return [
           'status' => true,
           'path' => $uploadPath
       ];
   } catch (Exception $e) {
       $this->logger->log('profile_picture_upload_error', [
           'user_id' => $userId,
           'error' => $e->getMessage()
       ]);

       return [
           'status' => false,
           'message' => 'خطا در آپلود تصویر پروفایل'
       ];
   }
}

// احراز هویت دو مرحله‌ای
public function setupTwoFactorAuth($userId) {
   // تولید کلید مخفی برای احراز هویت دو مرحله‌ای
   $secretKey = $this->generateTwoFactorSecret();

   try {
       // ذخیره کلید مخفی در دیتابیس
       $stmt = $this->db->prepare("
           UPDATE users 
           SET two_factor_secret = :secret, 
               two_factor_enabled = 1 
           WHERE id = :user_id
       ");
       $stmt->execute([
           ':secret' => password_hash($secretKey, PASSWORD_DEFAULT),
           ':user_id' => $userId
       ]);

       // تولید QR کد برای اپلیکیشن اح
       // تولید QR کد برای اپلیکیشن احراز هویت
       $qrCodeUrl = $this->generateTwoFactorQRCode($secretKey);

       // ثبت لاگ
       $this->logger->log('two_factor_setup', [
           'user_id' => $userId
       ]);

       return [
           'status' => true,
           'secret_key' => $secretKey,
           'qr_code_url' => $qrCodeUrl
       ];
   } catch (Exception $e) {
       $this->logger->log('two_factor_setup_error', [
           'user_id' => $userId,
           'error' => $e->getMessage()
       ]);

       return [
           'status' => false,
           'message' => 'خطا در راه‌اندازی احراز هویت دو مرحله‌ای'
       ];
   }
}

// تولید کلید مخفی برای احراز هویت دو مرحله‌ای
private function generateTwoFactorSecret() {
   // تولید کلید 32 کاراکتری با استفاده از الگوریتم امن
   $secret = base32_encode(random_bytes(20));
   return $secret;
}

// تولید QR کد برای اپلیکیشن احراز هویت
private function generateTwoFactorQRCode($secretKey) {
   $issuer = 'YourAppName';
   $accountName = 'user@example.com';

   $qrCodeUrl = "otpauth://totp/{$issuer}:{$accountName}?"
       . "secret={$secretKey}"
       . "&issuer={$issuer}"
       . "&algorithm=SHA1"
       . "&digits=6"
       . "&period=30";

   // تبدیل به QR کد با استفاده از کتابخانه QR
   return $this->qrCodeGenerator->generate($qrCodeUrl);
}

// تأیید کد احراز هویت دو مرحله‌ای
public function verifyTwoFactorCode($userId, $code) {
   try {
       // واکشی کلید مخفی کاربر
       $stmt = $this->db->prepare("SELECT two_factor_secret FROM users WHERE id = :user_id");
       $stmt->execute([':user_id' => $userId]);
       $secretKey = $stmt->fetchColumn();

       // بررسی اعتبار کد
       $isValid = $this->validateTwoFactorCode($secretKey, $code);

       if ($isValid) {
           // ثبت لاگ
           $this->logger->log('two_factor_verified', [
               'user_id' => $userId
           ]);

           return [
               'status' => true,
               'message' => 'کد احراز هویت تأیید شد'
           ];
       } else {
           // ثبت لاگ خطا
           $this->logger->log('two_factor_verification_failed', [
               'user_id' => $userId
           ]);

           return [
               'status' => false,
               'message' => 'کد احراز هویت نامعتبر است'
           ];
       }
   } catch (Exception $e) {
       $this->logger->log('two_factor_verification_error', [
           'user_id' => $userId,
           'error' => $e->getMessage()
       ]);

       return [
           'status' => false,
           'message' => 'خطا در تأیید کد احراز هویت'
       ];
   }
}

// اعتبارسنجی کد احراز هویت
private function validateTwoFactorCode($secretKey, $userCode) {
       // تنظیم محدوده زمانی برای اعتبار کد (30 ثانیه قبل و بعد)
       $timeSlices = [
           time(), // زمان فعلی
           time() - 30, // 30 ثانیه قبل
           time() + 30  // 30 ثانیه بعد
       ];

       foreach ($timeSlices as $timestamp) {
           // محاسبه کد TOTP
           $calculatedCode = $this->generateTOTPCode($secretKey, $timestamp);
           
           // مقایسه کد محاسبه شده با کد کاربر
           if (hash_equals($calculatedCode, $userCode)) {
               return true;
           }
       }

       return false;
   }

   // تولید کد TOTP
   private function generateTOTPCode($secretKey, $timestamp) {
       // دیکد کردن کلید base32
       $secretKey = base32_decode($secretKey);

       // محاسبه اسلایس زمانی
       $timeSlice = floor($timestamp / 30);

       // تبدیل اسلایس زمانی به بایت
       $binary = pack('N*', $timeSlice);
       $binary = str_pad($binary, 8, chr(0), STR_PAD_LEFT);

       // محاسبه هش HMAC-SHA1
       $hmac = hash_hmac('sha1', $binary, $secretKey, true);

       // محاسبه آفست
       $offset = ord(substr($hmac, -1)) & 0xF;
       $hashPart = substr($hmac, $offset, 4);
       $value = unpack('N', $hashPart)[1] & 0x7FFFFFFF;

       // تولید کد 6 رقمی
       $code = $value % 1000000;
       return str_pad($code, 6, '0', STR_PAD_LEFT);
   }

   // غیرفعال کردن احراز هویت دو مرحله‌ای
   public function disableTwoFactorAuth($userId) {
       try {
           $stmt = $this->db->prepare("
               UPDATE users 
               SET two_factor_secret = NULL, 
                   two_factor_enabled = 0 
               WHERE id = :user_id
           ");
           $result = $stmt->execute([':user_id' => $userId]);

           if ($result) {
               // ثبت لاگ
               $this->logger->log('two_factor_disabled', [
                   'user_id' => $userId
               ]);

               return [
                   'status' => true,
                   'message' => 'احراز هویت دو مرحله‌ای غیرفعال شد'
               ];
           } else {
               return [
                   'status' => false,
                   'message' => 'خطا در غیرفعال کردن احراز هویت دو مرحله‌ای'
               ];
           }
       } catch (Exception $e) {
           $this->logger->log('two_factor_disable_error', [
               'user_id' => $userId,
               'error' => $e->getMessage()
           ]);

           return [
               'status' => false,
               'message' => 'خطای سیستمی در غیرفعال کردن احراز هویت'
           ];
       }
   }

   // مدیریت سشن‌های فعال کاربر
   public function getActiveSessions($userId) {
       try {
           $stmt = $this->db->prepare("
               SELECT 
                   session_id, 
                   ip_address,
                   device_type, 
                    login_time, 
                    last_activity 
                FROM user_sessions 
                WHERE user_id = :user_id 
                AND is_active = 1 
                ORDER BY last_activity DESC
            ");
            $stmt->execute([':user_id' => $userId]);
            $activeSessions = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return [
                'status' => true,
                'sessions' => $activeSessions
            ];
        } catch (Exception $e) {
            $this->logger->log('active_sessions_fetch_error', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);

            return [
                'status' => false,
                'message' => 'خطا در دریافت سشن‌های فعال'
            ];
        }
    }

    // قطع سشن خاص
    public function terminateSession($userId, $sessionId) {
        try {
            $stmt = $this->db->prepare("
                UPDATE user_sessions 
                SET is_active = 0, 
                    terminated_at = NOW() 
                WHERE user_id = :user_id 
                AND session_id = :session_id
            ");
            $result = $stmt->execute([
                ':user_id' => $userId,
                ':session_id' => $sessionId
            ]);

            if ($result) {
                // ثبت لاگ
                $this->logger->log('session_terminated', [
                    'user_id' => $userId,
                    'session_id' => $sessionId
                ]);

                return [
                    'status' => true,
                    'message' => 'سشن با موفقیت قطع شد'
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'خطا در قطع سشن'
                ];
            }
        } catch (Exception $e) {
            $this->logger->log('session_termination_error', [
                'user_id' => $userId,
                'session_id' => $sessionId,
                'error' => $e->getMessage()
            ]);

            return [
                'status' => false,
                'message' => 'خطای سیستمی در قطع سشن'
            ];
        }
    }

    // بررسی وضعیت حریم خصوصی و امنیت
    public function getPrivacySettings($userId) {
        try {
            $stmt = $this->db->prepare("
                SELECT 
                    two_factor_enabled,
                    login_notifications_enabled,
                    profile_visibility,
                    email_visibility,
                    last_password_change
                FROM users 
                WHERE id = :user_id
            ");
            $stmt->execute([':user_id' => $userId]);
            $privacySettings = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($privacySettings) {
                return [
                    'status' => true,
                    'privacy_settings' => $privacySettings
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'تنظیمات حریم خصوصی یافت نشد'
                ];
            }
        } catch (Exception $e) {
            $this->logger->log('privacy_settings_fetch_error', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);

            return [
                'status' => false,
                'message' => 'خطا در دریافت تنظیمات حریم خصوصی'
            ];
        }
    }

    // بروزرسانی تنظیمات حریم خصوصی
    public function updatePrivacySettings($userId, $settings) {