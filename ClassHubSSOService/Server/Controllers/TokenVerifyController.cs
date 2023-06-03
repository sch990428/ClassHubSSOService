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
        public Task<IActionResult> VerifyToken([FromQuery] int user_id, [FromQuery] string accessToken)
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
                var token_user_id = claimsPrincipal.FindFirst("user_id").Value;
                var name = claimsPrincipal.FindFirst(ClaimTypes.Name).Value;
                var role = claimsPrincipal.FindFirst(ClaimTypes.Role).Value;

                Console.WriteLine("���̵�" + user_id);

                if (int.Parse(token_user_id) == user_id) {
                    string cacheConnection = "classhub-sso-chache-cheap.redis.cache.windows.net:6380,password=67jYcaIgYIAFqYLuyeOaNxarFsLNZUO74AzCaDSl6uo=,ssl=True,abortConnect=False";
                    ConnectionMultiplexer connection = ConnectionMultiplexer.Connect(cacheConnection);
                    IDatabase cache = connection.GetDatabase();
                    string savedToken = cache.StringGet(user_id + "_atoken");

                    if (savedToken == null) {
                        var result = new { Result = false, Code = -1, Message = "��ū�� ����Ǿ����ϴ�." }; 
                        return Task.FromResult<IActionResult>(Ok(result));
                    } else {
                        if (accessToken == savedToken) {
                            var result = new { Result = true, Code = 0, Message = "��������" };
                            return Task.FromResult<IActionResult>(Ok(result));
                        } else {
                            var result = new { Result = false, Code = -2, Message = "�ߺ� ������ �����Ǿ����ϴ�." };
                            return Task.FromResult<IActionResult>(Ok(result));
                        }
                    }
                } else {
                    var result = new { Result = false, Code = -3, Message = "�������� ����� ID�Դϴ�." };
                    return Task.FromResult<IActionResult>(Ok(result));
                }
            }
            catch (Exception ex)
            {
                //��ū ���� �������� ������ �� ��� �ϴ� ������ false ó��
                var result = new { Result = false, Code = -4, Message = "�������� ������ū�Դϴ�." + ex.Message };
                return Task.FromResult<IActionResult>(Ok(result));
            }
        }
    };
}