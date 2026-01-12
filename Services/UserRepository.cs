using System;
using System.Collections.Generic;
using System.Data;

namespace SafeVault.Repositories
{
    public interface IUserRepository
    {
        bool CreateUser(string username, string email, string password, string role);
        User GetUserById(int userId);
        User GetUserByUsername(string username);
        bool UpdateUser(User user);
        bool DeleteUser(int userId);
        List<User> GetAllUsers();
    }

    public class UserRepository : IUserRepository
    {
        private readonly DatabaseHelper _dbHelper;

        public UserRepository(string connectionString)
        {
            _dbHelper = new DatabaseHelper(connectionString);
        }

        public bool CreateUser(string username, string email, string password, string role)
        {
            // Validate inputs
            if (!InputValidator.IsValidUsername(username) || 
                !InputValidator.IsValidEmail(email) || 
                !InputValidator.IsStrongPassword(password))
            {
                return false;
            }

            // Hash password
            var (hash, salt) = PasswordHasher.HashPassword(password);

            // Use parameterized query
            string query = @"
                INSERT INTO Users (Username, Email, PasswordHash, Salt, Role, CreatedAt)
                VALUES (@Username, @Email, @PasswordHash, @Salt, @Role, @CreatedAt)";

            var parameters = new Dictionary<string, object>
            {
                { "Username", username },
                { "Email", email },
                { "PasswordHash", hash },
                { "Salt", salt },
                { "Role", role },
                { "CreatedAt", DateTime.UtcNow }
            };

            try
            {
                int rowsAffected = _dbHelper.ExecuteSecureNonQuery(query, parameters);
                return rowsAffected > 0;
            }
            catch
            {
                return false;
            }
        }

        public User GetUserById(int userId)
        {
            string query = @"
                SELECT UserID, Username, Email, Role, IsActive, CreatedAt
                FROM Users 
                WHERE UserID = @UserID";

            var parameters = new Dictionary<string, object>
            {
                { "UserID", userId }
            };

            var dataTable = _dbHelper.ExecuteSecureQuery(query, parameters);
            
            if (dataTable.Rows.Count == 0)
                return null;

            var row = dataTable.Rows[0];
            return new User
            {
                UserID = Convert.ToInt32(row["UserID"]),
                Username = row["Username"].ToString(),
                Email = row["Email"].ToString(),
                Role = row["Role"].ToString(),
                IsActive = Convert.ToBoolean(row["IsActive"]),
                CreatedAt = Convert.ToDateTime(row["CreatedAt"])
            };
        }

        public User GetUserByUsername(string username)
        {
            // Sanitize input
            string sanitizedUsername = InputValidator.SanitizeInput(username);

            string query = @"
                SELECT UserID, Username, Email, Role, IsActive, CreatedAt
                FROM Users 
                WHERE Username = @Username";

            var parameters = new Dictionary<string, object>
            {
                { "Username", sanitizedUsername }
            };

            var dataTable = _dbHelper.ExecuteSecureQuery(query, parameters);
            
            if (dataTable.Rows.Count == 0)
                return null;

            var row = dataTable.Rows[0];
            return new User
            {
                UserID = Convert.ToInt32(row["UserID"]),
                Username = row["Username"].ToString(),
                Email = row["Email"].ToString(),
                Role = row["Role"].ToString(),
                IsActive = Convert.ToBoolean(row["IsActive"]),
                CreatedAt = Convert.ToBoolean(row["CreatedAt"])
            };
        }

        public List<User> GetAllUsers()
        {
            string query = @"
                SELECT UserID, Username, Email, Role, IsActive, CreatedAt
                FROM Users 
                ORDER BY Username";

            var dataTable = _dbHelper.ExecuteSecureQuery(query);
            var users = new List<User>();

            foreach (DataRow row in dataTable.Rows)
            {
                users.Add(new User
                {
                    UserID = Convert.ToInt32(row["UserID"]),
                    Username = row["Username"].ToString(),
                    Email = row["Email"].ToString(),
                    Role = row["Role"].ToString(),
                    IsActive = Convert.ToBoolean(row["IsActive"]),
                    CreatedAt = Convert.ToDateTime(row["CreatedAt"])
                });
            }

            return users;
        }

        public bool UpdateUser(User user)
        {
            string query = @"
                UPDATE Users 
                SET Username = @Username, 
                    Email = @Email, 
                    Role = @Role, 
                    IsActive = @IsActive,
                    UpdatedAt = @UpdatedAt
                WHERE UserID = @UserID";

            var parameters = new Dictionary<string, object>
            {
                { "Username", InputValidator.SanitizeInput(user.Username) },
                { "Email", InputValidator.SanitizeInput(user.Email) },
                { "Role", user.Role },
                { "IsActive", user.IsActive },
                { "UpdatedAt", DateTime.UtcNow },
                { "UserID", user.UserID }
            };

            try
            {
                int rowsAffected = _dbHelper.ExecuteSecureNonQuery(query, parameters);
                return rowsAffected > 0;
            }
            catch
            {
                return false;
            }
        }

        public bool DeleteUser(int userId)
        {
            // Soft delete instead of hard delete
            string query = "UPDATE Users SET IsActive = 0 WHERE UserID = @UserID";
            
            var parameters = new Dictionary<string, object>
            {
                { "UserID", userId }
            };

            try
            {
                int rowsAffected = _dbHelper.ExecuteSecureNonQuery(query, parameters);
                return rowsAffected > 0;
            }
            catch
            {
                return false;
            }
        }
    }
}