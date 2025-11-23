using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NWebsec.AspNetCore.Middleware;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

var builder = WebApplication.CreateBuilder(args);

// DB: SQL Server (use secure connection string)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity with locked-down options
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Replace default PBKDF2 with Argon2 hasher
builder.Services.AddSingleton<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher>();

// MVC + anti-XSS
builder.Services.AddControllersWithViews()
    .AddRazorRuntimeCompilation()
    .AddMvcOptions(o =>
    {
        // Global anti-forgery for unsafe HTTP methods
        // In MVC, use [ValidateAntiForgeryToken] per action or filters:
    });

builder.Services.AddRazorPages();

builder.Services.AddAntiforgery(o =>
{
    o.SuppressXFrameOptionsHeader = false;
    o.Cookie.Name = "__SafeVault_AntiCsrf";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Security headers: HSTS, CSP, X-Content-Type-Options, X-XSS-Protection-like via CSP
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// CSP (script-src 'self'; no inline, add nonce where needed)
app.UseCsp(csp =>
{
    csp.DefaultSources(s => s.Self());
    csp.ScriptSources(s => s.Self());
    csp.StyleSources(s => s.Self().UnsafeInline()); // consider removing UnsafeInline if using nonces
    csp.ImageSources(s => s.Self().Data());
    csp.ObjectSources(s => s.None());
    csp.FrameAncestors(s => s.None());
    csp.BlockAllMixedContent();
});

app.UseXContentTypeOptions();
app.UseReferrerPolicy(opts => opts.NoReferrer());
app.UseXfo(xfo => xfo.Deny());
app.UseXXssProtection(options => options.EnabledWithBlockMode()); // legacy; CSP is primary

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Seed roles and an admin
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roles = new[] { "admin", "user" };
    foreach (var r in roles)
        if (!await roleManager.RoleExistsAsync(r))
            await roleManager.CreateAsync(new IdentityRole(r));

    var adminEmail = builder.Configuration["SeedAdmin:Email"];
    var adminPassword = builder.Configuration["SeedAdmin:Password"]; // keep in secrets
    if (!string.IsNullOrWhiteSpace(adminEmail) && !string.IsNullOrWhiteSpace(adminPassword))
    {
        var existing = await userManager.FindByEmailAsync(adminEmail);
        if (existing is null)
        {
            var admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                DisplayName = "SafeVault Admin"
            };
            var create = await userManager.CreateAsync(admin, adminPassword);
            if (create.Succeeded)
                await userManager.AddToRoleAsync(admin, "admin");
        }
    }
}

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
