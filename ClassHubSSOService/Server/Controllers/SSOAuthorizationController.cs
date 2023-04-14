using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Npgsql;
using SSOAuthorizationServer.Shared;
using System.Text.Json;
using System.Security.Cryptography;

namespace SSOAuthorizationServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SSOAuthorizarionController : ControllerBase
    {
        //�����ڵ� ��û
        [HttpPost]
        public async Task<IActionResult> POST([FromBody] AuthorizationCodeRequest request)
        {
            Console.WriteLine("[ID : " + request.Id + " PW : " + request.Password + "]�� ���� ���� ��û�� �����߽��ϴ�!");

            MemoryCache cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));
            string authCode = GenerateCode();

            var response = new AuthorizationCodeResponse { AuthorizationCode = authCode };
            string json = JsonSerializer.Serialize(response);

            return Ok(json);
        }
        private string GenerateCode()
        {
            using (var randomGenerator = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[8];
                randomGenerator.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }
        }
    };

    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> POST([FromBody] AccessTokenRequest request)
        {
            Console.WriteLine("[ID : " + request.AuthorizationCode + "]�� ���� ��ū �߱� ��û�� �����߽��ϴ�!");

            string Atoken = GenerateCode();
            string Rtoken = GenerateCode();
            var response = new AccessTokenResponse { AccessToken = Atoken, RefreshToken = Rtoken };
            string json = JsonSerializer.Serialize(response);
            return Ok(json);

        }

        private string GenerateCode()
        {
            using (var randomGenerator = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[8];
                randomGenerator.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }
        }
    };
}