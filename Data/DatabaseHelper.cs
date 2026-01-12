using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;

namespace SafeVault.Data
{
    public class DatabaseHelper : IDisposable
    {
        private readonly SqlConnection _connection;
        private readonly string _connectionString;

        public DatabaseHelper(string connectionString)
        {
            _connectionString = connectionString;
            _connection = new SqlConnection(connectionString);
        }

        // Secure parameterized query execution
        public DataTable ExecuteSecureQuery(string query, Dictionary<string, object> parameters = null)
        {
            var dataTable = new DataTable();
            
            try
            {
                _connection.Open();
                
                using (var command = new SqlCommand(query, _connection))
                {
                    // Add parameters to prevent SQL injection
                    if (parameters != null)
                    {
                        foreach (var param in parameters)
                        {
                            // Sanitize parameter values
                            object sanitizedValue = param.Value is string ? 
                                InputValidator.SanitizeInput(param.Value.ToString()) : 
                                param.Value;
                                
                            command.Parameters.AddWithValue("@" + param.Key, sanitizedValue ?? DBNull.Value);
                        }
                    }

                    using (var adapter = new SqlDataAdapter(command))
                    {
                        adapter.Fill(dataTable);
                    }
                }
            }
            catch (SqlException ex)
            {
                // Log SQL errors without exposing details
                LogError("SQL Error", ex.Message, query);
                throw new ApplicationException("Database operation failed");
            }
            finally
            {
                if (_connection.State == ConnectionState.Open)
                    _connection.Close();
            }

            return dataTable;
        }

        // Secure non-query execution (INSERT, UPDATE, DELETE)
        public int ExecuteSecureNonQuery(string query, Dictionary<string, object> parameters = null)
        {
            int rowsAffected = 0;
            
            try
            {
                _connection.Open();
                
                using (var command = new SqlCommand(query, _connection))
                {
                    // Add parameters
                    if (parameters != null)
                    {
                        foreach (var param in parameters)
                        {
                            object sanitizedValue = param.Value is string ? 
                                InputValidator.SanitizeInput(param.Value.ToString()) : 
                                param.Value;
                                
                            command.Parameters.AddWithValue("@" + param.Key, sanitizedValue ?? DBNull.Value);
                        }
                    }

                    rowsAffected = command.ExecuteNonQuery();
                }
            }
            catch (SqlException ex)
            {
                LogError("SQL Error", ex.Message, query);
                throw new ApplicationException("Database operation failed");
            }
            finally
            {
                if (_connection.State == ConnectionState.Open)
                    _connection.Close();
            }

            return rowsAffected;
        }

        // Secure scalar query
        public object ExecuteSecureScalar(string query, Dictionary<string, object> parameters = null)
        {
            object result = null;
            
            try
            {
                _connection.Open();
                
                using (var command = new SqlCommand(query, _connection))
                {
                    if (parameters != null)
                    {
                        foreach (var param in parameters)
                        {
                            object sanitizedValue = param.Value is string ? 
                                InputValidator.SanitizeInput(param.Value.ToString()) : 
                                param.Value;
                                
                            command.Parameters.AddWithValue("@" + param.Key, sanitizedValue ?? DBNull.Value);
                        }
                    }

                    result = command.ExecuteScalar();
                }
            }
            catch (SqlException ex)
            {
                LogError("SQL Error", ex.Message, query);
                throw new ApplicationException("Database operation failed");
            }
            finally
            {
                if (_connection.State == ConnectionState.Open)
                    _connection.Close();
            }

            return result;
        }

        private void LogError(string errorType, string message, string query)
        {
            // Log to secure logging system
            Console.Error.WriteLine($"[{DateTime.UtcNow}] {errorType}: {message}");
            Console.Error.WriteLine($"Query: {query}");
            
            // In production, log to secure logging service
            // Avoid logging sensitive data
        }

        public void Dispose()
        {
            _connection?.Dispose();
        }
    }
}