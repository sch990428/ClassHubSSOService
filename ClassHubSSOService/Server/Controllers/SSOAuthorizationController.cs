using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Npgsql;
using SSOAuthorizationServer.Shared;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using System.Data;

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
            Console.WriteLine("[ID : " + request.UserId + " PW : " + request.Password + "]�� ���� ���� ��û�� �����߽��ϴ�!");

            var connectionString = "Host=\r\nacademic-info-db.postgres.database.azure.com\r\n;Username=classhub;Password=ch55361!;Database=AcademicInfo";
            var academic_connection = new NpgsqlConnection(connectionString);
            var student_exist_query = "SELECT COUNT(*) FROM student WHERE id = @id";
            var professor_exist_query = "SELECT COUNT(*) FROM instructor WHERE id = @id";
            var parameters = new DynamicParameters();
            parameters.Add("id", int.Parse(request.UserId));

            if (academic_connection.ExecuteScalar<int>(student_exist_query, parameters) == 1) {

                string authCode = GenerateCode();

                var response = new AuthorizationCodeResponse { UserId = request.UserId, AuthorizationCode = authCode };
                string json = JsonSerializer.Serialize(response);
                Console.WriteLine("�л� �α���");
                return Ok(json);

            } else if (academic_connection.ExecuteScalar<int>(professor_exist_query, parameters) == 1) {

                string authCode = GenerateCode();

                var response = new AuthorizationCodeResponse { UserId = request.UserId, AuthorizationCode = authCode };
                string json = JsonSerializer.Serialize(response);
                Console.WriteLine("���� �α���");
                return Ok(json);

            } else {

                Console.WriteLine("�������� ����");
                return BadRequest();

            }
            
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
            Console.WriteLine("[ID : " + request.UserId + "]�� ���� ��ū �߱� ��û�� �����߽��ϴ�!");

            string role;
            string name;

            var connectionString = "Host=\r\nacademic-info-db.postgres.database.azure.com\r\n;Username=classhub;Password=ch55361!;Database=AcademicInfo";
            var academic_connection = new NpgsqlConnection(connectionString);
            var student_exist_query = "SELECT COUNT(*) FROM student WHERE id = @id";
            var parameters = new DynamicParameters();
            parameters.Add("id", int.Parse(request.UserId));

            if (academic_connection.ExecuteScalar<int>(student_exist_query, parameters) == 1) {
                role = "student";

                var student_name_query = "SELECT name FROM student WHERE id = @id";
                name = academic_connection.ExecuteScalar<string>(student_name_query, parameters);
            }
            else
            {
                role = "professor";

                var professor_name_query = "SELECT name FROM instructor WHERE id = @id";
                name = academic_connection.ExecuteScalar<string>(professor_name_query, parameters);
            }
            // JWT ��ū ����
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("ClassHubOnTheBuilding");

            var claims = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.Role, role),
                new Claim("user_id", request.UserId)
            });
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                                                     SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            string Atoken = tokenHandler.WriteToken(token);

            string Rtoken = RandomStringGenerator.GenerateRandomString(16);
            var response = new AccessTokenResponse { AccessToken = Atoken, RefreshToken = Rtoken };
            string json = JsonSerializer.Serialize(response);

            string cacheConnection = "classhub-sso-chache-cheap.redis.cache.windows.net:6380,password=67jYcaIgYIAFqYLuyeOaNxarFsLNZUO74AzCaDSl6uo=,ssl=True,abortConnect=False";
            ConnectionMultiplexer connection = ConnectionMultiplexer.Connect(cacheConnection);

            // ������ ����
            IDatabase cache = connection.GetDatabase();
            cache.StringSet(request.UserId + "_atoken", Atoken, TimeSpan.FromMinutes(60));
            cache.StringSet(request.UserId + "_rtoken", Rtoken, TimeSpan.FromDays(1));

            return Ok(json);
        }

        public class RandomStringGenerator {
            private static Random random = new Random();

            public static string GenerateRandomString(int length) {
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                return new string(Enumerable.Repeat(chars, length)
                  .Select(s => s[random.Next(s.Length)]).ToArray());
            }
        }
    };
}