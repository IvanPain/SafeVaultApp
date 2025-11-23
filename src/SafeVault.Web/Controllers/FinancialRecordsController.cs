using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;

namespace SafeVault.Web.Controllers
{
    [Authorize] // must be logged in
    public class FinancialRecordsController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;

        public FinancialRecordsController(ApplicationDbContext db, UserManager<ApplicationUser> userManager)
        {
            _db = db; _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            var uid = _userManager.GetUserId(User);
            var records = await _db.FinancialRecords.Where(r => r.OwnerUserId == uid)
                                                    .OrderByDescending(r => r.CreatedUtc)
                                                    .ToListAsync();
            return View(records);
        }

        [HttpGet]
        public IActionResult Create() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(FinancialRecordInput input)
        {
            if (!ModelState.IsValid) return View(input);

            var uid = _userManager.GetUserId(User);
            var model = new FinancialRecord
            {
                OwnerUserId = uid!,
                CreatedUtc = DateTime.UtcNow,
                MaskedAccountNumber = "****-****-****-1234",
                Amount = input.Amount,
                Currency = input.Currency,
                NotesSanitized = Sanitizer.SanitizeUserNotes(input.Notes)
            };
            _db.FinancialRecords.Add(model);
            await _db.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
s