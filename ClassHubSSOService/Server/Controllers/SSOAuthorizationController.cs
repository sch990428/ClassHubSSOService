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

namespace SSOAuthorizationServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SSOAuthorizarionController : ControllerBase
    {
        //인증코드 요청
        [HttpPost]
        public async Task<IActionResult> POST([FromBody] AuthorizationCodeRequest request)
        {
            Console.WriteLine("[ID : " + request.UserId + " PW : " + request.Password + "]에 대한 인증 요청이 도착했습니다!");

            MemoryCache cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));
            string authCode = GenerateCode();

            var response = new AuthorizationCodeResponse { UserId = request.UserId, AuthorizationCode = authCode };
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
            Console.WriteLine("[ID : " + request.UserId + "]에 대한 토큰 발급 요청이 도착했습니다!");

            string role;
            var connectionString = "Host=\r\nacademic-info-db.postgres.database.azure.com\r\n;Username=classhub;Password=ch55361!;Database=AcademicInfo";
            var role_connection = new NpgsqlConnection(connectionString);
            var student_exist_query = "SELECT COUNT(*) FROM student WHERE id = @id";
            var parameters = new DynamicParameters();
            parameters.Add("id", int.Parse(request.UserId));

            if (role_connection.ExecuteScalar<int>(student_exist_query, parameters) == 1) {
                role = "student"; 
            }
            else
            {
                role = "professor";
            }
                // JWT 토큰 생성
                var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("ClassHubOnTheBuilding");

            var claims = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, "Hello"),
                new Claim(ClaimTypes.Role, role),
                new Claim("user_id", request.UserId)
            });
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                                                     SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            string Atoken = tokenHandler.WriteToken(token);

            string Rtoken = GenerateCode();
            var response = new AccessTokenResponse { AccessToken = Atoken, RefreshToken = Rtoken };
            string json = JsonSerializer.Serialize(response);

            string cacheConnection = "classhub-sso-chache-cheap.redis.cache.windows.net:6380,password=67jYcaIgYIAFqYLuyeOaNxarFsLNZUO74AzCaDSl6uo=,ssl=True,abortConnect=False";
            ConnectionMultiplexer connection = ConnectionMultiplexer.Connect(cacheConnection);

            // 데이터 저장
            IDatabase cache = connection.GetDatabase();
            cache.StringSet(request.UserId + "_atoken", Atoken, TimeSpan.FromSeconds(60));

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