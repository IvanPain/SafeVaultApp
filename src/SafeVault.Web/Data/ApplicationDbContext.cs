using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Web.Data
{
    public class ApplicationUser : IdentityUser
    {
        // Add domain fields that are safe for storage, never store raw secrets here
        public string? DisplayName { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) {}

        // Example secure table for financial records
        public DbSet<FinancialRecord> FinancialRecords => Set<FinancialRecord>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<FinancialRecord>()
                .HasIndex(x => x.OwnerUserId);
        }
    }

    public class FinancialRecord
    {
        public int Id { get; set; }
        public string OwnerUserId { get; set; } = default!;
        public DateTime CreatedUtc { get; set; }
        public string MaskedAccountNumber { get; set; } = default!; // Never store full PAN
        public decimal Amount { get; set; }
        public string Currency { get; set; } = "USD";
        public string NotesSanitized { get; set; } = ""; // stored sanitized/escaped
    }
}
