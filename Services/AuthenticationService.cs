using System;
using System.Data;
using System.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace SafeVault.Services
{
    public interface IAuthenticationService
    {
        (bool Success, string Message, User User) Authenticate(string username, string password, string ipAddress);
        bool HasPermission(int userId, string requiredRole);
        void Logout(string sessionToken);
        bool ValidateSession(string sessionToken);
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly string _connectionString;
        private readonly ILogger<AuthenticationService> _logger;

        public AuthenticationService(string connectionString, ILogger<AuthenticationService> logger)
        {
            _connectionString = connectionString;
            _logger = logger;
        }

        public (bool Success, string Message, User User) Authenticate(string username, string password, string ipAddress)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();

                // Parameterized query to prevent SQL injection
                string query = @"
                    SELECT UserID, Username, Email, PasswordHash, Salt, Role, 
                           FailedLoginAttempts, AccountLockedUntil, IsActive
                    FROM Users 
                    WHERE Username = @Username OR Email = @Username";

                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    using (var reader = command.ExecuteReader())
                    {
                        if (!reader.Read())
                        {
                            LogAudit(null, "LOGIN_FAILED", $"Failed login attempt for username: {username}", ipAddress);
                            return (false, "Invalid username or password", null);
                        }

                        // Check if account is locked
                        if (reader["AccountLockedUntil"] != DBNull.Value)
                        {
                            DateTime lockUntil = (DateTime)reader["AccountLockedUntil"];
                            if (lockUntil > DateTime.UtcNow)
                            {
                                return (false, $"Account is locked until {lockUntil:yyyy-MM-dd HH:mm:ss}", null);
                            }
                        }

                        // Check if account is active
                        if (!(bool)reader["IsActive"])
                        {
                            return (false, "Account is deactivated", null);
                        }

                        string storedHash = reader["PasswordHash"].ToString();
                        string storedSalt = reader["Salt"].ToString();

                        // Verify password
                        if (!PasswordHasher.VerifyPassword(password, storedHash, storedSalt))
                        {
                            int failedAttempts = (int)reader["FailedLoginAttempts"] + 1;
                            
                            // Update failed login attempts
                            reader.Close();
                            UpdateFailedAttempts(connection, (int)reader["UserID"], failedAttempts, ipAddress);
                            
                            if (failedAttempts >= 5)
                            {
                                LockAccount(connection, (int)reader["UserID"], DateTime.UtcNow.AddMinutes(15));
                                return (false, "Account locked due to too many failed attempts", null);
                            }
                            
                            return (false, "Invalid username or password", null);
                        }

                        // Reset failed attempts on successful login
                        ResetFailedAttempts(connection, (int)reader["UserID"]);

                        // Update last login
                        UpdateLastLogin(connection, (int)reader["UserID"]);

                        // Create user object
                        var user = new User
                        {
                            UserID = (int)reader["UserID"],
                            Username = reader["Username"].ToString(),
                            Email = reader["Email"].ToString(),
                            Role = reader["Role"].ToString()
                        };

                        LogAudit(user.UserID, "LOGIN_SUCCESS", "User logged in successfully", ipAddress);
                        
                        return (true, "Authentication successful", user);
                    }
                }
            }
        }

        private void UpdateFailedAttempts(SqlConnection connection, int userId, int attempts, string ipAddress)
        {
            string query = "UPDATE Users SET FailedLoginAttempts = @Attempts WHERE UserID = @UserID";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Attempts", attempts);
                command.Parameters.AddWithValue("@UserID", userId);
                command.ExecuteNonQuery();
            }
            
            LogAudit(userId, "LOGIN_FAILED", $"Failed login attempt #{attempts}", ipAddress);
        }

        private void ResetFailedAttempts(SqlConnection connection, int userId)
        {
            string query = @"
                UPDATE Users 
                SET FailedLoginAttempts = 0, 
                    AccountLockedUntil = NULL 
                WHERE UserID = @UserID";
                
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@UserID", userId);
                command.ExecuteNonQuery();
            }
        }

        private void LockAccount(SqlConnection connection, int userId, DateTime lockUntil)
        {
            string query = "UPDATE Users SET AccountLockedUntil = @LockUntil WHERE UserID = @UserID";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@LockUntil", lockUntil);
                command.Parameters.AddWithValue("@UserID", userId);
                command.ExecuteNonQuery();
            }
            
            LogAudit(userId, "ACCOUNT_LOCKED", $"Account locked until {lockUntil}", null);
        }

        private void UpdateLastLogin(SqlConnection connection, int userId)
        {
            string query = "UPDATE Users SET LastLogin = @LastLogin WHERE UserID = @UserID";
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@LastLogin", DateTime.UtcNow);
                command.Parameters.AddWithValue("@UserID", userId);
                command.ExecuteNonQuery();
            }
        }

        public bool HasPermission(int userId, string requiredRole)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string query = "SELECT Role FROM Users WHERE UserID = @UserID AND IsActive = 1";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userId);
                    var role = command.ExecuteScalar()?.ToString();
                    
                    // Simple role hierarchy: admin > user
                    if (role == "admin") return true;
                    if (role == "user" && requiredRole == "user") return true;
                    
                    return false;
                }
            }
        }

        private void LogAudit(int? userId, string action, string description, string ipAddress)
        {
            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    
                    string query = @"
                        INSERT INTO AuditLog (UserID, Action, Description, IPAddress, Timestamp)
                        VALUES (@UserID, @Action, @Description, @IPAddress, @Timestamp)";
                        
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserID", userId.HasValue ? (object)userId.Value : DBNull.Value);
                        command.Parameters.AddWithValue("@Action", action);
                        command.Parameters.AddWithValue("@Description", description);
                        command.Parameters.AddWithValue("@IPAddress", string.IsNullOrEmpty(ipAddress) ? DBNull.Value : (object)ipAddress);
                        command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit trail");
            }
        }

        public void Logout(string sessionToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string query = "UPDATE UserSessions SET IsValid = 0 WHERE Token = @Token";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Token", sessionToken);
                    command.ExecuteNonQuery();
                }
            }
        }

        public bool ValidateSession(string sessionToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string query = @"
                    SELECT COUNT(*) 
                    FROM UserSessions 
                    WHERE Token = @Token 
                    AND IsValid = 1 
                    AND ExpiresAt > @Now";
                    
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Token", sessionToken);
                    command.Parameters.AddWithValue("@Now", DateTime.UtcNow);
                    
                    int count = (int)command.ExecuteScalar();
                    return count > 0;
                }
            }
        }
    }

    public class User
    {
        public int UserID { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
    }
}