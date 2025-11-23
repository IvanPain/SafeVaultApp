using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

public class AuthTests
{
    private (UserManager<ApplicationUser>, SignInManager<ApplicationUser>, ApplicationDbContext) BuildIdentity()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("AuthTestsDb")
            .Options;
        var ctx = new ApplicationDbContext(options);

        var store = new UserStore<ApplicationUser>(ctx);
        var userManager = new UserManager<ApplicationUser>(
            store,
            null,
            new Argon2PasswordHasher(),
            new IUserValidator<ApplicationUser>[] { new UserValidator<ApplicationUser>() },
            new IPasswordValidator<ApplicationUser>[] { new PasswordValidator<ApplicationUser>() },
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            null,
            null
        );

        var signInManager = TestHelpers.BuildSignInManager(userManager);

        return (userManager, signInManager, ctx);
    }

    [Fact]
    public async Task Valid_login_succeeds()
    {
        var (um, sm, ctx) = BuildIdentity();
        var user = new ApplicationUser { UserName = "user@example.com", Email = "user@example.com", EmailConfirmed = true };
        (await um.CreateAsync(user, "ValidPass!23456")).Succeeded.Should().BeTrue();

        var result = await sm.CheckPasswordSignInAsync(user, "ValidPass!23456", lockoutOnFailure: true);
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task Invalid_login_fails_and_may_lockout()
    {
        var (um, sm, ctx) = BuildIdentity();
        var user = new ApplicationUser { UserName = "bad@example.com", Email = "bad@example.com", EmailConfirmed = true };
        (await um.CreateAsync(user, "ValidPass!23456")).Succeeded.Should().BeTrue();

        for (int i = 0; i < 5; i++)
        {
            var result = await sm.CheckPasswordSignInAsync(user, "WrongPass", lockoutOnFailure: true);
        }
        var locked = await um.IsLockedOutAsync(user);
        locked.Should().BeTrue();
    }
}
