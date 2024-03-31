using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using mvc_app.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace mvc_app.Controllers
{
    public class LoginController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        Api.Api api;
        public LoginController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            api = new Api.Api(httpContextAccessor);
        }
        // GET: LoginController
        public ActionResult Index()
        {
            return View();
        }
        public async Task<ActionResult> Login(/*[Bind("Login,Password")]*/ UserLogin loginModel)
        {
            if (await Authorization(loginModel))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                TempData["IncorrectLogin"] = "Неверные данные";
                return RedirectToAction("Index", "Login");
            }
        }

        private async Task<bool> Authorization(UserLogin loginModel)
        {
            Api.TokenResponse tokens = await api.UserLoginAsync(loginModel.Login, loginModel.Password);
            if (tokens.AccessToken.Length != 0)
            {
                await Api.Api.SetTokenForClientAsync(tokens.AccessToken);


                var jwtHandler = new JwtSecurityTokenHandler();
                var readableToken = jwtHandler.ReadJwtToken(tokens.AccessToken);

                var claims = readableToken.Claims;
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                var roleClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
                if (roleClaim != null)
                {
                    var userRole = roleClaim.Value;
                    identity.AddClaim(new Claim(ClaimTypes.Role, "Администратор магазина"));
                    /*if (userRole == "Администратор магазина")
                    {
                      *//*  ViewBag.ShowAdminButton = true; // Показываем кнопку для администратора
                        ViewBag.ShowSysAdminButton = false;*//*

                    }
                    else if (userRole == "Системный администратор")
                    {
                       *//* ViewBag.ShowAdminButton = false;
                        ViewBag.ShowSysAdminButton = true;*//*
                    }
                    else if (userRole == "Клиент")
                    {
                     *//*   ViewBag.ShowSysAdminButton = true;
                        ViewBag.ShowAdminButton = false; // Скрываем кнопку для других пользователей*//*
                    }*/
                }
                /*var _token = new JwtSecurityTokenHandler().ReadJwtToken(token);
                var claims = _token.Claims;
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(principal);*/
                return true;
            }
            return false;
        }

/*        private async Task Authenticate(string token)
        {
            HttpContext.Response.Cookies.Append("token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
        }*/
    }
}
