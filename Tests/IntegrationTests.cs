using NUnit.Framework;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace SafeVault.IntegrationTests
{
    [TestFixture]
    public class IntegrationTests
    {
        private HttpClient _client;
        private string _baseUrl = "http://localhost:5000";

        [SetUp]
        public void Setup()
        {
            _client = new HttpClient { BaseAddress = new Uri(_baseUrl) };
        }

        [Test]
        public async Task TestLoginEndpointSecurity()
        {
            // Test SQL injection via login
            var sqlInjectionContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "admin'--"),
                new KeyValuePair<string, string>("password", "any")
            });

            var response = await _client.PostAsync("/login", sqlInjectionContent);
            Assert.AreNotEqual(HttpStatusCode.OK, response.StatusCode, 
                "SQL injection attempt should not succeed");
        }

        [Test]
        public async Task TestXSSInjection()
        {
            // Test XSS in form submission
            var xssContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "<script>alert(1)</script>"),
                new KeyValuePair<string, string>("email", "test@example.com")
            });

            var response = await _client.PostAsync("/register", xssContent);
            var responseBody = await response.Content.ReadAsStringAsync();
            
            Assert.IsFalse(responseBody.Contains("<script>"), 
                "Response should not contain unencoded script tags");
        }

        [Test]
        public async Task TestBruteForceProtection()
        {
            // Test multiple rapid login attempts
            for (int i = 0; i < 10; i++)
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", "testuser"),
                    new KeyValuePair<string, string>("password", "wrongpassword")
                });

                var response = await _client.PostAsync("/login", content);
                
                if (i >= 5)
                {
                    // After 5 attempts, should get locked out message
                    var responseBody = await response.Content.ReadAsStringAsync();
                    Assert.IsTrue(responseBody.Contains("locked") || 
                                 response.StatusCode == HttpStatusCode.TooManyRequests,
                        "Should indicate account lock after multiple failures");
                }
            }
        }
    }
}