using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

public class AuthorizationTests
{
    [Fact]
    public void Admin_policy_requires_admin_role()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddPolicy("CanExportFinancialRecords", policy => policy.RequireRole("admin"));
        });
        var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = provider.GetPolicyAsync("CanExportFinancialRecords").Result!;
        policy.Requirements.Should().ContainSingle(r => r is RolesAuthorizationRequirement req && req.AllowedRoles.Contains("admin"));
    }
}
