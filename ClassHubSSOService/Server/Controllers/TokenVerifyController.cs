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
            var key = Encoding.ASCII.GetBytes("ClassHubOnTheBuilding"); //��ĪŰ ��ȣȭ

            try
            {
                var validationParameters = new TokenValidationParameters //JWT��ū ���� ���� 
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                SecurityToken validatedToken;
                var claimsPrincipal = tokenHandler.ValidateToken(accessToken, validationParameters, out validatedToken);

                //��ū���κ��� ������ �̾Ƴ�
                var user_id = claimsPrincipal.FindFirst("user_id").Value;
                var name = claimsPrincipal.FindFirst(ClaimTypes.Name).Value;
                var role = claimsPrincipal.FindFirst(ClaimTypes.Role).Value;

                Console.WriteLine("���̵�" + user_id);

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
                //��ū ���� �������� ������ �� ��� �ϴ� ������ false ó��
                Console.WriteLine(ex.Message);
                return Task.FromResult<IActionResult>(Ok(false));
            }
        }
    };
}