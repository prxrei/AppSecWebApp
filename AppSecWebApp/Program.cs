using Microsoft.AspNetCore.Identity;
using AppSecWebApp.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString"));
    options.EnableSensitiveDataLogging(); 
    options.EnableDetailedErrors();       

});


builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); 
    options.Lockout.MaxFailedAccessAttempts = 3; 
})
.AddEntityFrameworkStores<AuthDbContext>();

builder.Services.AddDataProtection();
builder.Services.AddSingleton<ApplicationUser, ApplicationUser>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(60);
});

builder.Services.ConfigureApplicationCookie(config =>
{
    config.LoginPath = "/Login";
});

builder.Services.AddAuthentication("Cookie").AddCookie("Cookie", options
    =>
{
    options.Cookie.Name = "Cookie";

    options.AccessDeniedPath = "/Account/AccessDenied";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Errors");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStatusCodePagesWithRedirects("/ErrorsPages/{0}");
app.UseStaticFiles();

app.UseRouting();

app.UseSession();

app.UseAuthentication();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
