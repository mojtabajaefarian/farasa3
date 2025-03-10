<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/User.php';
require_once __DIR__ . '/Product.php';

class Comment
{
       private $conn;
       private $table_name = 'comments';

       //Properties
       public $id;
       public $product_id;
       public $user_id;
       public $content;
       public $rating;
       public $created_at;
       public $updated_at;

       // Constructor
       public function __construct($db)
       {
              $this->conn = $db;
       }

       // Create new comment
       public function createComment()
       {
              $query = "INSERT INTO " . $this->table_name . " 
                  (product_id, user_id, content, rating, created_at) 
                  VALUES 
                  (:product_id, :user_id, :content, :rating, NOW())";

              $stmt = $this->conn->prepare($query);

              // Sanitize and validate input
              $this->product_id = htmlspecialchars(strip_tags($this->product_id));
              $this->user_id = htmlspecialchars(strip_tags($this->user_id));
              $this->content = htmlspecialchars(strip_tags($this->content));
              $this->rating = filter_var($this->rating, FILTER_VALIDATE_INT);

              // Bind parameters
              $stmt->bindParam(":product_id", $this->product_id);
              $stmt->bindParam(":user_id", $this->user_id);
              $stmt->bindParam(":content", $this->content);
              $stmt->bindParam(":rating", $this->rating);

              if ($stmt->execute()) {
                     $this->id = $this->conn->lastInsertId();
                     return true;
              }

              return false;
       }

       // Update existing comment
       public function updateComment()
       {
              $query = "UPDATE " . $this->table_name . "
                  SET content = :content, 
                      rating = :rating, 
                      updated_at = NOW()
                  WHERE id = :id AND user_id = :user_id";

              $stmt = $this->conn->prepare($query);

              // Sanitize and validate input
              $this->content = htmlspecialchars(strip_tags($this->content));
              $this->rating = filter_var($this->rating, FILTER_VALIDATE_INT);
              $this->id = htmlspecialchars(strip_tags($this->id));
              $this->user_id = htmlspecialchars(strip_tags($this->user_id));

              // Bind parameters
              $stmt->bindParam(":content", $this->content);
              $stmt->bindParam(":rating", $this->rating);
              $stmt->bindParam(":id", $this->id);
              $stmt->bindParam(":user_id", $this->user_id);

              return $stmt->execute();
       }

       // Delete comment
       public function deleteComment()
       {
              $query = "DELETE FROM " . $this->table_name . "
                  WHERE id = :id AND user_id = :user_id";

              $stmt = $this->conn->prepare($query);

              // Sanitize input
              $this->id = htmlspecialchars(strip_tags($this->id));
              $this->user_id = htmlspecialchars(strip_tags($this->user_id));

              // Bind parameters
              $stmt->bindParam(":id", $this->id);
              $stmt->bindParam(":user_id", $this->user_id);

              return $stmt->execute();
       }

       // Get comments for a specific product
       public function getProductComments($product_id, $limit = 10, $offset = 0)
       {
              $query = "SELECT c.*, u.full_name, u.username 
                  FROM " . $this->table_name . " c
                  JOIN users u ON c.user_id = u.id
                  WHERE c.product_id = :product_id
                  ORDER BY c.created_at DESC
                  LIMIT :limit OFFSET :offset";

              $stmt = $this->conn->prepare($query);

              // Sanitize inputs
              $product_id = htmlspecialchars(strip_tags($product_id));
              $limit = filter_var($limit, FILTER_VALIDATE_INT);
              $offset = filter_var($offset, FILTER_VALIDATE_INT);

              // Bind parameters
              $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
              $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);

              $stmt->execute();
              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Get total comment count for a product
       public function getCommentCount($product_id)
       {
              $query = "SELECT COUNT(*) as comment_count 
                  FROM " . $this->table_name . "
                  WHERE product_id = :product_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);
              return $result['comment_count'];
       }

       // Calculate average rating for a product
       public function getProductAverageRating($product_id)
       {
              $query = "SELECT AVG(rating) as average_rating 
                  FROM " . $this->table_name . "
                  WHERE product_id = :product_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);
              return round($result['average_rating'], 1);
       }

       // Check if user has already commented on a product
       public function hasUserCommented($product_id, $user_id)
       {
              $query = "SELECT COUNT(*) as comment_count 
                  FROM " . $this->table_name . "
                  WHERE product_id = :product_id AND user_id = :user_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              $stmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);
              return $result['comment_count'] > 0;
       }

       // Validate comment data
       private function validateCommentData()
       {
              $errors = [];

              // Validate product_id
              if (!filter_var($this->product_id, FILTER_VALIDATE_INT)) {
                     $errors[] = "Invalid product ID";
              }

              // Validate user_id
              if (!filter_var($this->user_id, FILTER_VALIDATE_INT)) {
                     $errors[] = "Invalid user ID";
              }

              // Validate content
              if (empty($this->content)) {
                     $errors[] = "Comment content cannot be empty";
              }

              if (strlen($this->content) > 500) {
                     $errors[] = "Comment content cannot exceed 500 characters";
              }

              // Validate rating
              if (!filter_var($this->rating, FILTER_VALIDATE_INT, [
                     'options' => [
                            'min_range' => 1,
                            'max_range' => 5
                     ]
              ])) {
                     $errors[] = "Rating must be between 1 and 5";
              }

              return $errors;
       }

       // Get single comment by ID
       public function getCommentById($comment_id)
       {
              $query = "SELECT c.*, u.full_name, u.username, p.name as product_name
                 FROM " . $this->table_name . " c
                 JOIN users u ON c.user_id = u.id
                 JOIN products p ON c.product_id = p.id
                 WHERE c.id = :comment_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
              $stmt->execute();

              return $stmt->fetch(PDO::FETCH_ASSOC);
       }

       // Admin: Get all comments with filtering and pagination
       public function getAllComments($filters = [], $limit = 10, $offset = 0)
       {
              $where_clauses = [];
              $params = [];

              // Optional filters
              if (!empty($filters['product_id'])) {
                     $where_clauses[] = "c.product_id = :product_id";
                     $params[':product_id'] = $filters['product_id'];
              }

              if (!empty($filters['user_id'])) {
                     $where_clauses[] = "c.user_id = :user_id";
                     $params[':user_id'] = $filters['user_id'];
              }

              if (!empty($filters['min_rating'])) {
                     $where_clauses[] = "c.rating >= :min_rating";
                     $params[':min_rating'] = $filters['min_rating'];
              }

              if (!empty($filters['max_rating'])) {
                     $where_clauses[] = "c.rating <= :max_rating";
                     $params[':max_rating'] = $filters['max_rating'];
              }

              $where_sql = $where_clauses ? "WHERE " . implode(" AND ", $where_clauses) : "";

              $query = "SELECT c.*, u.full_name, u.username, p.name as product_name
                 FROM " . $this->table_name . " c
                 JOIN users u ON c.user_id = u.id
                 JOIN products p ON c.product_id = p.id
                 $where_sql
                 ORDER BY c.created_at DESC
                 LIMIT :limit OFFSET :offset";

              $stmt = $this->conn->prepare($query);

              // Bind filter parameters
              foreach ($params as $key => $value) {
                     $stmt->bindValue($key, $value);
              }

              $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
              $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

              $stmt->execute();
              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Report a comment
       public function reportComment($comment_id, $user_id, $reason)
       {
              $query = "INSERT INTO comment_reports 
                 (comment_id, user_id, reason, created_at) 
                 VALUES 
                 (:comment_id, :user_id, :reason, NOW())";

              $stmt = $this->conn->prepare($query);

              // Sanitize inputs
              $comment_id = htmlspecialchars(strip_tags($comment_id));
              $user_id = htmlspecialchars(strip_tags($user_id));
              $reason = htmlspecialchars(strip_tags($reason));

              $stmt->bindParam(":comment_id", $comment_id);
              $stmt->bindParam(":user_id", $user_id);
              $stmt->bindParam(":reason", $reason);

              return $stmt->execute();
       }

       // Get comment reports (admin function)
       public function getCommentReports($limit = 10, $offset = 0)
       {
              $query = "SELECT cr.*, c.content as comment_content, 
                        u.username as reporter_username, 
                        cu.username as commented_user
                 FROM comment_reports cr
JOIN comments c ON cr.comment_id = c.id
                  JOIN users u ON cr.user_id = u.id
                  JOIN users cu ON c.user_id = cu.id
                  ORDER BY cr.created_at DESC
                  LIMIT :limit OFFSET :offset";

              $stmt = $this->conn->prepare($query);
              $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
              $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

              $stmt->execute();
              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Handle comment moderation
       public function moderateComment($comment_id, $action)
       {
              switch ($action) {
                     case 'approve':
                            $query = "UPDATE comments SET status = 'approved' WHERE id = :comment_id";
                            break;
                     case 'reject':
                            $query = "UPDATE comments SET status = 'rejected' WHERE id = :comment_id";
                            break;
                     case 'hidden':
                            $query = "UPDATE comments SET status = 'hidden' WHERE id = :comment_id";
                            break;
                     default:
                            return false;
              }

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);

              return $stmt->execute();
       }

       // Advanced search for comments
       public function searchComments($searchTerm, $filters = [], $limit = 10, $offset = 0)
       {
              $where_clauses = [];
              $params = [];

              // Search term in comment content or product name
              if (!empty($searchTerm)) {
                     $where_clauses[] = "(c.content LIKE :search_term OR p.name LIKE :search_term)";
                     $params[':search_term'] = "%{$searchTerm}%";
              }

              // Additional filters
              if (!empty($filters['start_date'])) {
                     $where_clauses[] = "c.created_at >= :start_date";
                     $params[':start_date'] = $filters['start_date'];
              }

              if (!empty($filters['end_date'])) {
                     $where_clauses[] = "c.created_at <= :end_date";
                     $params[':end_date'] = $filters['end_date'];
              }

              if (!empty($filters['status'])) {
                     $where_clauses[] = "c.status = :status";
                     $params[':status'] = $filters['status'];
              }

              $where_sql = $where_clauses ? "WHERE " . implode(" AND ", $where_clauses) : "";

              $query = "SELECT c.*, u.full_name, u.username, p.name as product_name
                  FROM " . $this->table_name . " c
                  JOIN users u ON c.user_id = u.id
                  JOIN products p ON c.product_id = p.id
                  $where_sql
                  ORDER BY c.created_at DESC
                  LIMIT :limit OFFSET :offset";

              $stmt = $this->conn->prepare($query);

              // Bind filter parameters
              foreach ($params as $key => $value) {
                     $stmt->bindValue($key, $value);
              }

              $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
              $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

              $stmt->execute();
              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Generate comment statistics
       public function getCommentStatistics($period = 'monthly')
       {
              switch ($period) {
                     case 'daily':
                            $query = "SELECT 
                            DATE(created_at) as period, 
                            COUNT(*) as total_comments,
                            AVG(rating) as average_rating
                          FROM " . $this->table_name . "
                          GROUP BY DATE(created_at)
                          ORDER BY period DESC LIMIT 30";
                            break;
                     case 'monthly':
                            $query = "SELECT 
                            DATE_FORMAT(created_at, '%Y-%m') as period, 
                            COUNT(*) as total_comments,
                            AVG(rating) as average_rating,
                            COUNT(DISTINCT user_id) as unique_commenters
                          FROM " . $this->table_name . "
                          GROUP BY period
                          ORDER BY period DESC
                          LIMIT 12";
                            break;
                     case 'yearly':
                            $query = "SELECT 
                            YEAR(created_at) as period, 
                            COUNT(*) as total_comments,
                            AVG(rating) as average_rating,
                            COUNT(DISTINCT user_id) as unique_commenters,
                            COUNT(DISTINCT product_id) as unique_products
                          FROM " . $this->table_name . "
                          GROUP BY period
                          ORDER BY period DESC
                          LIMIT 5";
                            break;
                     default:
                            throw new Exception("Invalid statistics period");
              }

              $stmt = $this->conn->prepare($query);
              $stmt->execute();
              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Check comment ownership
       public function isCommentOwner($comment_id, $user_id)
       {
              $query = "SELECT COUNT(*) as is_owner 
                  FROM " . $this->table_name . "
                  WHERE id = :comment_id AND user_id = :user_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
              $stmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);
              return $result['is_owner'] > 0;
       }

       // Bulk actions for comments
       public function bulkCommentAction($comment_ids, $action)
       {
              if (empty($comment_ids) || !in_array($action, ['delete', 'hide', 'approve'])) {
                     return false;
              }

              // Convert array to comma-separated string for SQL
              $comment_ids_str = implode(',', array_map('intval', $comment_ids));

              switch ($action) {
                     case 'delete':
                            $query = "DELETE FROM " . $this->table_name . " 
                          WHERE id IN ($comment_ids_str)";
                            break;
                     case 'hide':
                            $query = "UPDATE " . $this->table_name . " 
                          SET status = 'hidden' 
                          WHERE id IN ($comment_ids_str)";
                            break;
                     case 'approve':
                            $query = "UPDATE " . $this->table_name . " 
                          SET status = 'approved' 
                          WHERE id IN ($comment_ids_str)";
                            break;
              }

              $stmt = $this->conn->prepare($query);
              return $stmt->execute();
       }

       // Sanitize and validate comment before saving
       public function sanitizeCommentData()
       {
              $errors = [];

              // Trim and sanitize content
              $this->content = trim(strip_tags($this->content));

              // Validate content length
              if (empty($this->content)) {
                     $errors[] = "Comment cannot be empty";
              }

              if (strlen($this->content) > 500) {
                     $errors[] = "Comment must be less than 500 characters";
              }

              // Validate rating
              if ($this->rating < 1 || $this->rating > 5) {
                     $errors[] = "Rating must be between 1 and 5";
              }

              // Validate foreign key constraints
              $this->checkProductExists();
              $this->checkUserExists();

              return $errors;
       }

       // Check if referenced product exists
       private function checkProductExists()
       {
              $query = "SELECT COUNT(*) as product_count 
                 FROM products 
                 WHERE id = :product_id AND status = 'active'";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $this->product_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);

              if ($result['product_count'] == 0) {
                     throw new Exception("Product does not exist or is not active");
              }
       }

       // Check if user exists and is active
       private function checkUserExists()
       {
              $query = "SELECT COUNT(*) as user_count 
                 FROM users 
                 WHERE id = :user_id AND status = 'active'";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":user_id", $this->user_id, PDO::PARAM_INT);
              $stmt->execute();

              $result = $stmt->fetch(PDO::FETCH_ASSOC);

              if ($result['user_count'] == 0) {
                     throw new Exception("User does not exist or is not active");
              }
       }

       // Generate notification for comment
       public function generateCommentNotification()
       {
              // Get product owner and other interested parties
              $query = "SELECT u.id, u.email, u.notification_preferences
                 FROM products p
                 JOIN users u ON p.user_id = u.id
                 WHERE p.id = :product_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $this->product_id, PDO::PARAM_INT);
              $stmt->execute();

              $notificationRecipients = $stmt->fetchAll(PDO::FETCH_ASSOC);

              foreach ($notificationRecipients as $recipient) {
                     // Check notification preferences
                     if ($this->shouldSendNotification($recipient['notification_preferences'])) {
                            $this->sendNotification($recipient['id'], $recipient['email']);
                     }
              }
       }

       // Determine if notification should be sent
       private function shouldSendNotification($preferences)
       {
              $notificationSettings = json_decode($preferences, true);
              return $notificationSettings['comment_notifications'] ?? false;
       }

       // Send actual notification
       private function sendNotification($userId, $email)
       {
              // Create notification record
              $query = "INSERT INTO notifications 
                 (user_id, type, message, related_id, created_at) 
                 VALUES 
                 (:user_id, 'comment', :message, :comment_id, NOW())";

              $message = "New comment added to your product";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":user_id", $userId, PDO::PARAM_INT);
              $stmt->bindParam(":message", $message);
              $stmt->bindParam(":comment_id", $this->id, PDO::PARAM_INT);
              $stmt->execute();

              // Optional: Send email notification
              $this->sendEmailNotification($email, $message);
       }

       // Send email notification
       private function sendEmailNotification($email, $message)
       {
              // Email sending logic
              $headers = "From: notifications@yoursite.com\r\n";
              $headers .= "MIME-Version: 1.0\r\n";
              $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

              $emailBody = "<html>
           <body>
               <h2>New Comment Notification</h2>
               <p>{$message}</p>
           </body>
       </html>";

              mail($email, "New Comment Notification", $emailBody, $headers);
       }

       // Method to get most helpful comments
       public function getMostHelpfulComments($product_id, $limit = 5)
       {
              $query = "SELECT c.*, u.full_name, u.avatar,
                        (c.likes_count - c.dislikes_count) as helpfulness_score
                 FROM " . $this->table_name . " c
                 JOIN users u ON c.user_id = u.id
                 WHERE c.product_id = :product_id
                 ORDER BY helpfulness_score DESC, c.created_at DESC
                 LIMIT :limit";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
              $stmt->execute();

              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Like/Dislike comment functionality
       public function handleCommentReaction($comment_id, $user_id, $reaction)
       {
              // First, check if user has already reacted
              $checkQuery = "SELECT reaction FROM comment_reactions 
                      WHERE comment_id = :comment_id AND user_id = :user_id";

              $checkStmt = $this->conn->prepare($checkQuery);
              $checkStmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
              $checkStmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
              $checkStmt->execute();

              $existingReaction = $checkStmt->fetchColumn();

              // Start transaction
              $this->conn->beginTransaction();

              try {
                     if ($existingReaction) {
                            // Remove existing reaction if same as new reaction
                            if ($existingReaction === $reaction) {
                                   $deleteQuery = "DELETE FROM comment_reactions 
                                   WHERE comment_id = :comment_id AND user_id = :user_id";
                                   $deleteStmt = $this->conn->prepare($deleteQuery);
                                   $deleteStmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
                                   $deleteStmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
                                   $deleteStmt->execute();

                                   // Update comment counters
                                   $this->updateCommentReactionCounters($comment_id, $reaction, -1);
                            } else {
                                   // Update existing reaction
                                   $updateQuery = "UPDATE comment_reactions 
                                   SET reaction = :reaction 
                                   WHERE comment_id = :comment_id AND user_id = :user_id";
                                   $updateStmt = $this->conn->prepare($updateQuery);
                                   $updateStmt->bindParam(":reaction", $reaction);
                                   $updateStmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
                                   $updateStmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
                                   $updateStmt->execute();

                                   // Update comment counters
                                   $this->updateCommentReactionCounters($comment_id, $existingReaction, -1);
                                   $this->updateCommentReactionCounters($comment_id, $reaction, 1);
                            }
                     } else {
                            // Add new reaction
                            $insertQuery = "INSERT INTO comment_reactions 
                               (comment_id, user_id, reaction, created_at) 
                               VALUES 
                               (:comment_id, :user_id, :reaction, NOW())";
                            $insertStmt = $this->conn->prepare($insertQuery);
                            $insertStmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
                            $insertStmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
                            $insertStmt->bindParam(":reaction", $reaction);
                            $insertStmt->execute();

                            // Update comment counters
                            $this->updateCommentReactionCounters($comment_id, $reaction, 1);
                     }

                     // Commit transaction
                     $this->conn->commit();
                     return true;
              } catch (Exception $e) {
                     // Rollback transaction on error
                     $this->conn->rollBack();
                     error_log("Comment Reaction Error: " . $e->getMessage());
                     return false;
              }
       }

       // Update comment reaction counters
       private function updateCommentReactionCounters($comment_id, $reaction, $increment)
       {
              $query = $reaction === 'like'
                     ? "UPDATE comments SET likes_count = likes_count + :increment WHERE id = :comment_id"
                     : "UPDATE comments SET dislikes_count = dislikes_count + :increment WHERE id = :comment_id";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":increment", $increment, PDO::PARAM_INT);
              $stmt->bindParam(":comment_id", $comment_id, PDO::PARAM_INT);
              $stmt->execute();
       }

       // Advanced comment analytics
       public function getCommentAnalytics($product_id = null)
       {
              $whereClause = $product_id ? "WHERE product_id = :product_id" : "";

              $query = "SELECT 
COUNT(*) as total_comments,
AVG(rating) as average_rating,
COUNT(DISTINCT user_id) as unique_commenters,
SUM(likes_count) as total_likes,
SUM(dislikes_count) as total_dislikes,
ROUND(AVG(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) * 100, 2) as positive_rating_percentage,
(SELECT rating 
 FROM comments 
 $whereClause 
 GROUP BY rating 
 ORDER BY COUNT(*) DESC 
 LIMIT 1) as most_common_rating
FROM " . $this->table_name . "
$whereClause";

              $stmt = $this->conn->prepare($query);

              if ($product_id) {
                     $stmt->bindParam(":product_id", $product_id, PDO::PARAM_INT);
              }

              $stmt->execute();
              return $stmt->fetch(PDO::FETCH_ASSOC);
       }

       // Generate comment sentiment analysis
       public function analyzeSentiment($text)
       {
              // Simple sentiment analysis using keyword matching
              $positiveWords = [
                     'خوب',
                     'عالی',
                     '최고',
                     'fantastic',
                     'excellent',
                     'amazing',
                     'great',
                     'wonderful',
                     'superb'
              ];

              $negativeWords = [
                     'بد',
                     'ضعیف',
                     'terrible',
                     'awful',
                     'poor',
                     'horrible',
                     'disappointing',
                     'bad'
              ];

              $text = mb_strtolower($text);
              $positiveCount = 0;
              $negativeCount = 0;

              foreach ($positiveWords as $word) {
                     $positiveCount += substr_count($text, mb_strtolower($word));
              }

              foreach ($negativeWords as $word) {
                     $negativeCount += substr_count($text, mb_strtolower($word));
              }

              $totalWords = count(preg_split('/\s+/', $text));

              $sentimentScore = ($positiveCount - $negativeCount) / $totalWords;

              return [
                     'sentiment_score' => $sentimentScore,
                     'sentiment_type' => $sentimentScore > 0 ? 'positive' : ($sentimentScore < 0 ? 'negative' : 'neutral')
              ];
       }

       // Method to export comments
       public function exportComments($filters = [], $format = 'csv')
       {
              $comments = $this->getAllComments($filters, 10000);

              switch ($format) {
                     case 'csv':
                            return $this->exportToCSV($comments);
                     case 'json':
                            return $this->exportToJSON($comments);
                     case 'excel':
                            return $this->exportToExcel($comments);
                     default:
                            throw new Exception("Invalid export format");
              }
       }

       // Export comments to CSV
       private function exportToCSV($comments)
       {
              $filename = "comments_export_" . date('Y-m-d_H-i-s') . ".csv";

              // Open file for writing
              $fp = fopen('php://output', 'w');

              // Set headers for file download
              header('Content-Type: text/csv');
              header('Content-Disposition: attachment; filename="' . $filename . '"');

              // Write CSV headers
              $headers = [
                     'ID',
                     'Product',
                     'User',
                     'Content',
                     'Rating',
                     'Likes',
                     'Dislikes',
                     'Created At',
                     'Status'
              ];
              fputcsv($fp, $headers);

              // Write comment data
              foreach ($comments as $comment) {
                     fputcsv($fp, [
                            $comment['id'],
                            $comment['product_name'],
                            $comment['username'],
                            $comment['content'],
                            $comment['rating'],
                            $comment['likes_count'],
                            $comment['dislikes_count'],
                            $comment['created_at'],
                            $comment['status']
                     ]);
              }

              fclose($fp);
              exit();
       }

       // Export comments to JSON
       private function exportToJSON($comments)
       {
              $filename = "comments_export_" . date('Y-m-d_H-i-s') . ".json";

              header('Content-Type: application/json');
              header('Content-Disposition: attachment; filename="' . $filename . '"');

              echo json_encode($comments, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
              exit();
       }





       function numToAlpha($n)
       {
              $n--;
              for ($r = ""; $n >= 0; $n = intval($n / 26) - 1)
                     $r = chr($n % 26 + 0x41) . $r;
              return $r;
       }






       // Export comments to Excel (requires PhpSpreadsheet library)
       private function exportToExcel($comments)
       {
              if (!class_exists('\PhpOffice\PhpSpreadsheet\Spreadsheet')) {
                     throw new Exception("PhpSpreadsheet library not installed");
              }

              $spreadsheet = new \PhpOffice\PhpSpreadsheet\Spreadsheet();
              $sheet = $spreadsheet->getActiveSheet();

              // Set column headers
              $headers = [
                     'ID',
                     'Product',
                     'User',
                     'Content',
                     'Rating',
                     'Likes',
                     'Dislikes',
                     'Created At',
                     'Status'
              ];

              // Write headers
              /*    foreach ($headers as $col => $header) {
                     $sheet->setCellValue($col + 1, 1, $header);
              }*/
              foreach ($headers as $col => $header) {
                     $cell = numToAlpha($col + 1) . '1'; // تبدیل عدد ستون به نام ستون و ترکیب با شماره ردیف
                     $sheet->setCellValue($cell, $header);
              }
              // Write comment data
              foreach ($comments as $row => $comment) {
                     $sheet->setCellValue('A' . ($row + 2), $comment['id']);
                     $sheet->setCellValue('B' . ($row + 2), $comment['product_name']);
                     $sheet->setCellValue('C' . ($row + 2), $comment['username']);
                     $sheet->setCellValue('D' . ($row + 2), $comment['content']);
                     $sheet->setCellValue('E' . ($row + 2), $comment['rating']);
                     $sheet->setCellValue('F' . ($row + 2), $comment['likes_count']);
                     $sheet->setCellValue('G' . ($row + 2), $comment['dislikes_count']);
                     $sheet->setCellValue('H' . ($row + 2), $comment['created_at']);
                     $sheet->setCellValue('I' . ($row + 2), $comment['status']);
              }

              // Generate file
              $filename = "comments_export_" . date('Y-m-d_H-i-s') . ".xlsx";

              // Redirect output to a client's web browser
              header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
              header('Content-Disposition: attachment;filename="' . $filename . '"');
              header('Cache-Control: max-age=0');

              $writer = \PhpOffice\PhpSpreadsheet\IOFactory::createWriter($spreadsheet, 'Xlsx');
              $writer->save('php://output');
              exit();
       }

       // Machine learning based comment recommendation
       public function getRecommendedComments($user_id, $product_id, $limit = 5)
       {
              // Collaborative filtering approach
              $query = "WITH user_comment_similarity AS (
          SELECT 
              c2.id as recommended_comment_id,
              COUNT(DISTINCT c1.user_id) as similarity_score
          FROM comments c1
          JOIN comments c2 ON c1.product_id = c2.product_id
          WHERE c1.user_id = :user_id 
          AND c2.user_id != :user_id
          AND c1.rating BETWEEN c2.rating - 1 AND c2.rating + 1
          GROUP BY c2.id
          ORDER BY similarity_score DESC
          LIMIT :limit
      )

      SELECT 
          c.*, 
          u.username, 
          u.avatar,
          ucs.similarity_score
      FROM user_comment_similarity ucs
      JOIN comments c ON ucs.recommended_comment_id = c.id
      JOIN users u ON c.user_id = u.id
      ORDER BY ucs.similarity_score DESC";

              $stmt = $this->conn->prepare($query);
              $stmt->bindParam(":user_id", $user_id, PDO::PARAM_INT);
              $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
              $stmt->execute();

              return $stmt->fetchAll(PDO::FETCH_ASSOC);
       }

       // Advanced spam detection
       public function detectSpam($comment_content)
       {
              $spamChecks = [
                     // Check for excessive links
                     'link_count' => substr_count($comment_content, 'http') > 2,

                     // Check for repeated characters
                     'repeated_chars' => preg_match('/(.)\1{5,}/', $comment_content),

                     // Check for known spam keywords
                     'spam_keywords' => preg_match('/\b(viagra|casino|loan|debt)\b/i', $comment_content),

                     // Check for all uppercase text
                     'all_caps' => ctype_upper($comment_content),

                     // Check for non-language characters
                     'non_language_ratio' => $this->calculateNonLanguageRatio($comment_content) > 0.3
              ];

              $spamScore = 0;
              foreach ($spamChecks as $check => $result) {
                     $spamScore += $result ? 1 : 0;
              }

              return [
                     'is_spam' => $spamScore >= 2,
                     'spam_score' => $spamScore,
                     'spam_details' => $spamChecks
              ];
       }

       // Calculate ratio of non-language characters
       private function calculateNonLanguageRatio($text)
       {
              $totalChars = mb_strlen($text);
              $nonLanguageChars = preg_match_all('/[^a-zA-Z0-9\s\p{L}]/u', $text);

              return $nonLanguageChars / $totalChars;
       }

       // Comment toxicity analysis
       // Hate speech and toxic language detection
       public function analyzeToxicity($comment_content)
       {
              $toxicityChecks = [
                     'profanity' => $this->checkProfanity($comment_content),
                     'personal_attacks' => $this->detectPersonalAttacks($comment_content),
                     'hate_speech' => $this->detectHateSpeech($comment_content),
                     'aggressive_language' => $this->detectAggressiveLanguage($comment_content)
              ];

              $toxicityScore = 0;
              foreach ($toxicityChecks as $check => $result) {
                     $toxicityScore += $result['score'];
              }

              return [
                     'is_toxic' => $toxicityScore > 2,
                     'toxicity_score' => $toxicityScore,
                     'toxicity_details' => $toxicityChecks
              ];
       }

       // Check for profanity
       private function checkProfanity($text)
       {
              $profanityList = [
                     // English profanity
                     'fuck',
                     'shit',
                     'damn',
                     'bitch',
                     // Persian profanity
                     'کیر',
                     'کون',
                     'ننه',
                     'پدر',
                     // Arabic profanity
                     'حمار',
                     'خنزير'
              ];

              $foundProfanity = [];
              $score = 0;

              foreach ($profanityList as $word) {
                     if (stripos($text, $word) !== false) {
                            $foundProfanity[] = $word;
                            $score++;
                     }
              }

              return [
                     'has_profanity' => !empty($foundProfanity),
                     'profanity_words' => $foundProfanity,
                     'score' => $score
              ];
       }

       // Detect personal attacks
       private function detectPersonalAttacks($text)
       {
              $attackPatterns = [
                     '/\b(احمق|بی\s?عرضه|نادان|خنگ)\b/u',
                     '/\b(stupid|idiot|moron|dumb)\b/i',
                     '/\b(تو هیچ\s?چی نمی\s?فهمی|لایق نیستی)\b/u'
              ];

              $foundAttacks = [];
              $score = 0;

              foreach ($attackPatterns as $pattern) {
                     if (preg_match($pattern, $text, $matches)) {
                            $foundAttacks[] = $matches[0];
                            $score++;
                     }
              }

              return [
                     'has_personal_attacks' => !empty($foundAttacks),
                     'attack_phrases' => $foundAttacks,
                     'score' => $score
              ];
       }

       // Detect hate speech
       private function detectHateSpeech($text)
       {
              $hateSpeechPatterns = [
                     // Racist terms
                     '/\b(نژاد\s?پرست|عرب|فارس|کرد)\b/u',
                     // Discriminatory language
                     '/\b(کافر|مشرک|غیر\s?مسلمان)\b/u',
                     // Derogatory group references
                     '/\b(قوم|قبیله|اقلیت)\s?(پست|ناقص|بی\s?ارزش)\b/u'
              ];

              $foundHateSpeech = [];
              $score = 0;

              foreach ($hateSpeechPatterns as $pattern) {
                     if (preg_match($pattern, $text, $matches)) {
                            $foundHateSpeech[] = $matches[0];
                            $score++;
                     }
              }

              return [
                     'has_hate_speech' => !empty($foundHateSpeech),
                     'hate_speech_phrases' => $foundHateSpeech,
                     'score' => $score
              ];
       }

       // Detect aggressive language
       // Detect aggressive language
       private function detectAggressiveLanguage($text)
       {
              $aggressivePatterns = [
                     // Threatening language
                     '/\b(تهدید|می\s?کشمت|حالت\s?رو\s?می\s?گیرم)\b/u',
                     // Violent expressions
                     '/\b(له\s?کنم|بزنم\s?تو\s?دهنت|نابود\s?کنم)\b/u',
                     // Intense negative language
                     '/\b(نابود|destroy|crush|annihilate)\b/i',
                     // Extreme emotional language
                     '/\b(متنفرم|از\s?همه\s?متنفرم|نابود\s?شو)\b/u'
              ];

              $intensityMultipliers = [
                     'بسیار' => 1.5,
                     'خیلی' => 1.3,
                     'extremely' => 1.4,
                     'totally' => 1.2
              ];

              $foundAggressivePhrases = [];
              $score = 0;
              $intensity = 1.0;

              // Check for intensity multipliers
              foreach ($intensityMultipliers as $word => $multiplier) {
                     if (stripos($text, $word) !== false) {
                            $intensity *= $multiplier;
                     }
              }

              foreach ($aggressivePatterns as $pattern) {
                     if (preg_match($pattern, $text, $matches)) {
                            $foundAggressivePhrases[] = $matches[0];
                            $score += $intensity;
                     }
              }

              return [
                     'has_aggressive_language' => !empty($foundAggressivePhrases),
                     'aggressive_phrases' => $foundAggressivePhrases,
                     'score' => $score,
                     'intensity' => $intensity
              ];
       }

       // Advanced comment content analysis
       public function analyzeCommentContent($comment_content)
       {
              $analysis = [
                     'length' => [
                            'total_chars' => mb_strlen($comment_content),
                            'word_count' => str_word_count($comment_content),
                            'is_comprehensive' => str_word_count($comment_content) > 10
                     ],
                     'language_quality' => $this->checkLanguageQuality($comment_content),
                     'sentiment' => $this->analyzeSentiment($comment_content),
                     'spam_detection' => $this->detectSpam($comment_content),
                     'toxicity_analysis' => $this->analyzeToxicity($comment_content)
              ];

              // Compute overall comment quality score
              $qualityScore = $this->computeCommentQualityScore($analysis);

              return [
                     'detailed_analysis' => $analysis,
                     'overall_quality_score' => $qualityScore
              ];
       }

       // Compute comment quality score
       private function computeCommentQualityScore($analysis)
       {
              $scoreComponents = [
                     'length_score' => $analysis['length']['is_comprehensive'] ? 2 : 0,
                     'language_quality_score' => $analysis['language_quality']['score'] * 2,
                     'sentiment_score' => $analysis['sentiment']['sentiment_score'] > 0 ? 2 : -1,
                     'spam_penalty' => $analysis['spam_detection']['is_spam'] ? -3 : 0,
                     'toxicity_penalty' => $analysis['toxicity_analysis']['is_toxic'] ? -4 : 0
              ];

              $totalScore = array_sum($scoreComponents);

              // Normalize score
              $normalizedScore = max(0, min(10, ($totalScore + 10) / 2));

              return round($normalizedScore, 2);
       }

       // Check language quality and writing style
       private function checkLanguageQuality($text)
       {
              // Placeholder implementation for language quality check
              $grammarComplexity = $this->checkGrammarComplexity($text);
              $spellingErrors = $this->checkSpellingErrors($text);

              return [
                     'grammar_complexity' => $grammarComplexity,
                     'spelling_errors' => $spellingErrors,
                     'score' => $grammarComplexity - $spellingErrors
              ];
       }

       // Placeholder method for checking grammar complexity
       private function checkGrammarComplexity($text)
       {
              // Implement grammar complexity check logic here
              return rand(1, 10); // Example: return a random score between 1 and 10
       }

       // Placeholder method for checking spelling errors
       private function checkSpellingErrors($text)
       {
              // Implement spelling error check logic here
              return rand(0, 5); // Example: return a random number of spelling errors
       }
       // Check language quality and writing style
       private function checkLanguageQuality($text)
       {
              $languageChecks = [
                     'grammar_complexity' => $this->checkGrammarComplexity($text),
                     'coherence' => $this->checkCoherence($text),
                     'vocabulary_richness' => $this->measureVocabularyRichness($text),
                     'sentence_structure' => $this->analyzeSentenceStructure($text)
              ];

              // Calculate overall language quality score
              $score = 0;
              foreach ($languageChecks as $check) {
                     $score += $check['score'];
              }

              return [
                     'language_checks' => $languageChecks,
                     'score' => $score / count($languageChecks),
                     'overall_quality' => $this->interpretLanguageQuality($score)
              ];
       }

       // Check grammar complexity
       private function checkGrammarComplexity($text)
       {
              $complexityMetrics = [
                     'clause_count' => $this->countClauses($text),
                     'verb_variety' => $this->measureVerbVariety($text),
                     'punctuation_usage' => $this->analyzePunctuationUsage($text)
              ];

              $complexityScore = 0;
              foreach ($complexityMetrics as $metric => $value) {
                     $complexityScore += $value;
              }

              return [
                     'complexity_metrics' => $complexityMetrics,
                     'score' => $complexityScore / count($complexityMetrics)
              ];
       }

       // Count clauses in text
       private function countClauses($text)
       {
              // Simple clause counting using regex
              $clausePatterns = [
                     '/\bو\b/',           // Persian conjunctions
                     '/\bکه\b/',           // Persian relative clause marker
                     '/\bاما\b/',          // Persian 'but'
                     '/,/',                // Comma as clause separator
                     '/؛/'                 // Persian semicolon
              ];

              $clauseCount = 1;  // Start with base clause
              foreach ($clausePatterns as $pattern) {
                     $clauseCount += preg_match_all($pattern, $text);
              }

              return min($clauseCount, 10);  // Cap at 10 for scoring
       }

       // Measure verb variety
       private function measureVerbVariety($text)
       {
              // Extract unique verbs using simple regex
              preg_match_all('/\b(می\s?[^\s]+|[^\s]+\s?کردن|[^\s]+\s?شدن)\b/u', $text, $matches);

              $uniqueVerbs = array_unique($matches[0]);
              $verbVarietyScore = count($uniqueVerbs) / 10;  // Normalize score

              return min($verbVarietyScore, 1);
       }

       // Analyze punctuation usage
       private function analyzePunctuationUsage($text)
       {
              $punctuationTypes = [
                     'periods' => substr_count($text, '.'),
                     'commas' => substr_count($text, ','),
                     'semicolons' => substr_count($text, '؛'),
                     'question_marks' => substr_count($text, '؟')
              ];

              $punctuationScore = 0;
              foreach ($punctuationTypes as $type => $count) {
                     $punctuationScore += ($count > 0 ? 0.25 : 0);
              }

              return $punctuationScore;
       }

       // Check text coherence
       private function checkCoherence($text)
       {
              $coherenceMetrics = [
                     'transition_words' => $this->checkTransitionWords($text),
                     'logical_flow' => $this->assessLogicalFlow($text)
              ];

              $coherenceScore = array_sum($coherenceMetrics) / count($coherenceMetrics);

              return [
                     'coherence_metrics' => $coherenceMetrics,
                     'score' => $coherenceScore
              ];
       }
}
