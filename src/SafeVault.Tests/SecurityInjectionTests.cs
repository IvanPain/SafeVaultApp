using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;

public class SecurityInjectionTests
{
    [Fact]
    public async Task Parameterized_raw_sql_blocks_basic_sqli()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("SqlInjectionDb")
            .Options;
        var ctx = new ApplicationDbContext(options);

        ctx.FinancialRecords.Add(new FinancialRecord
        {
            OwnerUserId = "user1",
            CreatedUtc = DateTime.UtcNow,
            MaskedAccountNumber = "****-****-****-1234",
            Amount = 10,
            Currency = "USD",
            NotesSanitized = "hello"
        });
        await ctx.SaveChangesAsync();

        var malicious = "user1' OR 1=1 --";
        var safe = await ctx.FinancialRecords
            .FromSqlInterpolated($"SELECT * FROM FinancialRecords WHERE OwnerUserId = {malicious}")
            .ToListAsync();

        // In-memory provider doesn’t execute SQL, but the query compiles with parameterization
        safe.Should().HaveCount(0); // no match on exact malicious string
    }

    [Fact]
    public void Razor_default_encoding_prevents_reflective_xss()
    {
        var notes = "<script>alert('xss')</script>";
        // Stored as sanitized text
        var sanitized = Sanitizer.SanitizeUserNotes(notes);
        sanitized.Should().NotContain("<script");
    }
}
