using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace SafeVault.Middleware
{
    public class RoleBasedAuthorizationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string[] _allowedRoles;

        public RoleBasedAuthorizationMiddleware(RequestDelegate next, string[] allowedRoles)
        {
            _next = next;
            _allowedRoles = allowedRoles;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Get user ID from session/claim
            var userId = context.Session.GetInt32("UserId");
            
            if (!userId.HasValue)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized");
                return;
            }

            // Get authentication service
            var authService = context.RequestServices.GetService<IAuthenticationService>();
            
            bool hasPermission = false;
            foreach (var role in _allowedRoles)
            {
                if (authService.HasPermission(userId.Value, role))
                {
                    hasPermission = true;
                    break;
                }
            }

            if (!hasPermission)
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Forbidden");
                return;
            }

            await _next(context);
        }
    }

    // Extension method for easy use
    public static class AuthorizationMiddlewareExtensions
    {
        public static IApplicationBuilder RequireRole(
            this IApplicationBuilder builder,
            params string[] roles)
        {
            return builder.UseMiddleware<RoleBasedAuthorizationMiddleware>(roles);
        }
    }
}