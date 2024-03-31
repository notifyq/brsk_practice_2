using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var config = new ConfigurationBuilder()
           .SetBasePath(Directory.GetCurrentDirectory())
           .AddJsonFile("appsettings.json")
           .Build();

var authOptions = config.GetSection("AuthOptions");
string key = authOptions["KEY"];




builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // указывает, будет ли валидироваться издатель при валидации токена
            ValidateIssuer = true,

            // строка, представляющая издателя
            // будет ли валидироваться потребитель токена
            ValidateAudience = true,
            // установка потребителя токена
            // будет ли валидироваться время существования
            ValidateLifetime = true,
            // установка ключа безопасности
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(key)),
            // валидация ключа безопасности
            ValidateIssuerSigningKey = true,
            ValidIssuer = "http://localhost/",
            ValidAudience = "http://localhost/",

            LifetimeValidator = (notBefore, expires, token, parameters) =>
            {
                var jwtToken = token as JwtSecurityToken;
                if (jwtToken == null) return false;

                var tokenTypeClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "token_type");
                if (tokenTypeClaim != null && tokenTypeClaim.Value == "refresh")
                {
                    // Если это refresh токен, отклоняем запрос
                    Console.WriteLine("Это refresh токен");
                    return false;
                }

                // Если это access токен, проверяем срок его действия
                return expires > DateTime.UtcNow;
            }
        };
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
