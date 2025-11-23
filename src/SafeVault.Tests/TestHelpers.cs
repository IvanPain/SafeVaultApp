using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SafeVault.Web.Data;

public static class TestHelpers
{
    public static SignInManager<ApplicationUser> BuildSignInManager(UserManager<ApplicationUser> userManager)
    {
        var context = new Mock<IHttpContextAccessor>();
        var claimsFactory = new UserClaimsPrincipalFactory<ApplicationUser>(userManager, new OptionsWrapper<IdentityOptions>(new IdentityOptions()));
        return new SignInManager<ApplicationUser>(userManager, context.Object, claimsFactory, null, null, null, null);
    }
}
