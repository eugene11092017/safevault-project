using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Security
{
    public static class InputValidator
    {
        // Sanitize input by removing potentially harmful characters
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove HTML tags
            string sanitized = Regex.Replace(input, "<.*?>", string.Empty);
            
            // Encode special characters
            sanitized = HttpUtility.HtmlEncode(sanitized);
            
            // Remove SQL injection patterns
            string[] sqlKeywords = { 
                "--", ";", "'", "\"", "/*", "*/", "@@", 
                "char", "nchar", "varchar", "nvarchar", 
                "alter", "begin", "cast", "create", "cursor", 
                "declare", "delete", "drop", "end", "exec", 
                "execute", "fetch", "insert", "kill", "open", 
                "select", "sys", "sysobjects", "syscolumns", 
                "table", "update" 
            };

            foreach (var keyword in sqlKeywords)
            {
                sanitized = Regex.Replace(sanitized, 
                    keyword, 
                    string.Empty, 
                    RegexOptions.IgnoreCase);
            }

            return sanitized.Trim();
        }

        // Validate username
        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            return Regex.IsMatch(username, @"^[a-zA-Z0-9_-]{3,20}$");
        }

        // Validate email
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            return Regex.IsMatch(email, 
                @"^[^@\s]+@[^@\s]+\.[^@\s]+$", 
                RegexOptions.IgnoreCase);
        }

        // Validate password strength
        public static bool IsStrongPassword(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 8)
                return false;

            // At least one uppercase, one lowercase, one digit, one special character
            return Regex.IsMatch(password, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$");
        }

        // Prevent XSS by encoding output
        public static string SafeOutput(string input)
        {
            return HttpUtility.HtmlEncode(input);
        }
    }
}