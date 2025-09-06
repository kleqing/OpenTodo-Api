using System.Text;
using System.Text.Json;
using dotenv.net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenTodo.Application.Services.Auth;
using OpenTodo.Application.Services.Email;
using OpenTodo.Application.Services.Role;
using OpenTodo.Domain.Entities;
using OpenTodo.Domain.Interfaces;
using OpenTodo.Domain.Jwt;
using OpenTodo.Infrastructure.Auth;
using OpenTodo.Infrastructure.Data;
using OpenTodo.Infrastructure.Repositories;
using OpenTodo.Shared.Utils;
using StackExchange.Redis;

namespace OpenTodo.WebApi;

public class Program
{
    public static async Task Main(string[] args)
    {
        //* Load .env file
        DotEnv.Load();

        var builder = WebApplication.CreateBuilder(args);
        const string myCors = "MyCorsPolicy";
        var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        builder.Services.AddScoped<IAuthTokenProcess, AuthTokenProcess>();
        builder.Services.AddScoped<IAuthorizeServices, AuthorizeServices>();
        builder.Services.AddScoped<IUserRepository, UserRepository>();
        builder.Services.AddTransient<IEmailSender, EmailSender>();
        builder.Services.AddSingleton<CloudinaryUploader>();
        
        builder.Services.AddIdentity<Users, IdentityRole<Guid>>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        //* Add Bearer Authentication
        builder.Services.Configure<Jwt>(options =>
        {
            options.Secret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? string.Empty;
            options.Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? string.Empty;
            options.Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? string.Empty;
            options.ExpiryInMinutes = int.Parse(Environment.GetEnvironmentVariable("JWT_EXPIRY_MINUTES") ?? "15");
        });
        
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "OpenTodo API",
                Version = "v1",
                Description = "API for OpenTodo application"
            });
            
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "Please enter a valid token"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] { }
                }
            });
        });

        builder.Services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy =
                    JsonNamingPolicy.CamelCase; //* Use original property names
                options.JsonSerializerOptions.PropertyNameCaseInsensitive =
                    true; //* Enable case-insensitive property names
            });

        builder.Services.AddCors(options =>
        {
            options.AddPolicy(myCors,
                policy =>
                {
                    policy.WithOrigins("https://localhost:3000", "http://localhost:3000")
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
                });
        });

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer("Bearer", _ => { })
            .AddGoogle(options =>
            {
                var clientId = options.ClientId =
                    Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? string.Empty;
                var clientSecret = options.ClientSecret =
                    Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? string.Empty;
                
                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                {
                    throw new Exception("Google ClientId or ClientSecret is missing");
                }
                
                options.ClientId = clientId;
                options.ClientSecret = clientSecret;
                options.ClaimActions.MapJsonKey("picture", "picture");
                options.SaveTokens = true;
                options.CallbackPath = "/signin-google";
            });

        builder.Services.PostConfigure<JwtBearerOptions>("Bearer", options =>
        {
            var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER")!;
            var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE")!;
            var secret = Environment.GetEnvironmentVariable("JWT_SECRET")!;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ClockSkew = TimeSpan.Zero, //* Disable the default 5-minute clock skew
                RequireExpirationTime = true //* Require the token to have an expiration time
            };
        });
        
        
        
        //* Redis Cache
        builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            var redisConnectionString = Environment.GetEnvironmentVariable("REDIS_CONNECTION_STRING");

            if (string.IsNullOrWhiteSpace(redisConnectionString))
            {
                throw new InvalidOperationException("Redis connection string is not set in environment variables.");
            }

            var configurationOptions = ConfigurationOptions.Parse(redisConnectionString, true);
            configurationOptions.AbortOnConnectFail = false;

            try
            {
                return ConnectionMultiplexer.Connect(configurationOptions);
            }
            catch (RedisConnectionException ex)
            {
                throw new InvalidOperationException("Failed to connect to Redis: " + ex.Message, ex);
            }
        });
        
        builder.Services.AddScoped<IDatabase>(sp =>
        {
            var connectionMultiplexer = sp.GetRequiredService<IConnectionMultiplexer>();
            return connectionMultiplexer.GetDatabase();
        });
        
        //* Email Confirmation
        builder.Services.Configure<IdentityOptions>(options => { options.SignIn.RequireConfirmedEmail = true; });

        // Add services to the container.
        builder.Services.AddAuthorization();
        builder.Services.AddHttpContextAccessor();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        else
        {
            app.UseExceptionHandler("/error"); // Custom error handling endpoint
            app.UseHsts();
        }

        //* Seed roles
        using (var scope = app.Services.CreateScope())
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
            await RoleServices.SeedRole(roleManager);
        }

        app.UseCors(myCors);
        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}