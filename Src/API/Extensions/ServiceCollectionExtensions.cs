using Application.Abstracts.Repositories;
using Application.Abstracts.Services;
using Application.Options;
using Application.Validations.CityValidation;
using Application.Validations.DistrictValidation;
using Application.Validations.PropertyAdValidation;
using Domain.Constants;
using Domain.Entities;
using FluentValidation;
using Infrastructure.Extensions;
using Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Persistence.Context;
using Persistence.Repositories;
using Persistence.Services;
using System.Text;
using System.Text.Json.Serialization;

namespace API.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
            });

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.CustomSchemaIds(t => t.FullName);

            // JWT Security Definition (Authorize button üçün)
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT yaz: Bearer {token}"
            });

            // JWT Security Requirement (bütün endpoint-lərə tətbiq)
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
                    new List<string>()
                }
            });
        });

        return services;
    }

    public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
    {
        // MinIO client + options
        services.AddMinioStorage(configuration);
        services.AddScoped<IFileStorageService, S3MinioFileStorageService>();

        // Validators
        services.AddValidatorsFromAssemblyContaining<CreatePropertyAdValidator>();
        services.AddValidatorsFromAssemblyContaining<UpdatePropertyAdValidator>();
        services.AddValidatorsFromAssemblyContaining<CreateCityValidator>();
        services.AddValidatorsFromAssemblyContaining<UpdateCityValidator>();
        services.AddValidatorsFromAssemblyContaining<CreateDistrictValidator>();
        services.AddValidatorsFromAssemblyContaining<UpdateDistrictValidator>();
        services.AddValidatorsFromAssemblyContaining<Application.Validations.Auth.RegisterRequestValidator>();

        // DbContext
        services.AddDbContext<BinaLiteDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        // Identity
        services.AddIdentity<User, IdentityRole>(opt =>
        {
            opt.User.RequireUniqueEmail = true;

            opt.Password.RequiredLength = 8;
            opt.Password.RequireDigit = true;
            opt.Password.RequireLowercase = true;
            opt.Password.RequireUppercase = true;
            opt.Password.RequireNonAlphanumeric = true;
        })
        .AddEntityFrameworkStores<BinaLiteDbContext>()
        .AddDefaultTokenProviders();

        // Options
        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
        services.Configure<SeedOptions>(configuration.GetSection(SeedOptions.SectionName));

        // Jwt section oxu (yoxdursa exception)
        var jwt = configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
                  ?? throw new InvalidOperationException("Jwt section tapılmadı (appsettings.json)");

        // Authentication (JWT Bearer)
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = jwt.Issuer,
                ValidAudience = jwt.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Secret)),

                ClockSkew = TimeSpan.Zero
            };
        });

        // Cookie redirect-ləri söndür (API üçün 401/403)
        services.ConfigureApplicationCookie(o =>
        {
            o.Events.OnRedirectToLogin = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            o.Events.OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        // Authorization (policy)
        services.AddAuthorization(options =>
        {
            options.AddPolicy(Policies.ManageCities, p => p.RequireRole(RoleNames.Admin));
            options.AddPolicy(Policies.ManageProperties, p => p.RequireAuthenticatedUser());
        });

        // Servis qeydləri
        services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
        services.AddScoped<IAuthService, AuthService>();

        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();

        // AutoMapper
        services.AddAutoMapper(cfg =>
        {
            cfg.ShouldMapMethod = method => false;
        }, AppDomain.CurrentDomain.GetAssemblies());

        // Repos + Services
        services.AddScoped<IPropertyAdRepository, PropertyAdRepository>();
        services.AddScoped<IPropertyAdService, PropertyAdService>();
        services.AddScoped<IPropertyMediaRepository, PropertyMediaRepository>();

        services.AddScoped<ICityRepository, CityRepository>();
        services.AddScoped<ICityService, CityService>();

        services.AddScoped<IDistrictRepository, DistrictRepository>();
        services.AddScoped<IDistrictService, DistrictService>();

        services.AddScoped<IFileService, FileService>();

        return services;
    }
}
