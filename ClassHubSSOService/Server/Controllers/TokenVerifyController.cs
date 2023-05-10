using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Npgsql;
using SSOAuthorizationServer.Shared;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using System.Data;
using System.Xml.Linq;

namespace ClassHubSSO.Server.Controllers
{
    [ApiController]
    [Route("api/token/verify")]
    public class TokenVerifyController : ControllerBase
    {
        [HttpGet]
        public Task<IActionResult> VerifyToken([FromQuery] string accessToken)
        {
            Console.WriteLine(accessToken);
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("ClassHubOnTheBuilding"); //대칭키 암호화

            try
            {
                var validationParameters = new TokenValidationParameters //JWT토큰 검증 정보 
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                SecurityToken validatedToken;
                var claimsPrincipal = tokenHandler.ValidateToken(accessToken, validationParameters, out validatedToken);

                //토큰으로부터 정보를 뽑아냄
                var user_id = claimsPrincipal.FindFirst("user_id").Value;
                var name = claimsPrincipal.FindFirst(ClaimTypes.Name).Value;
                var role = claimsPrincipal.FindFirst(ClaimTypes.Role).Value;

                Console.WriteLine("아이디" + user_id);

                string cacheConnection = "classhub-sso-cache.redis.cache.windows.net:6380,password=7Ke76ORsQpWOiyIFGvc82ycd8T8ztN2x0AzCaEF7DgU=,ssl=True,abortConnect=False";
                ConnectionMultiplexer connection = ConnectionMultiplexer.Connect(cacheConnection);
                IDatabase cache = connection.GetDatabase();
                string savedToken = cache.StringGet(user_id+"_atoken");

                if (accessToken == savedToken)
                {
                    return Task.FromResult<IActionResult>(Ok(true));
                }
                else
                {
                    return Task.FromResult<IActionResult>(Ok(false));
                }
            }
            catch (Exception ex)
            {
                //토큰 검증 과정에서 오류가 난 경우 일단 무조건 false 처리
                Console.WriteLine(ex.Message);
                return Task.FromResult<IActionResult>(Ok(false));
            }
        }
    };
}