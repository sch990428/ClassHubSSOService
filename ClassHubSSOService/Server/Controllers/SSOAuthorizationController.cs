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
using System.Text.RegularExpressions;
using System.Collections.Generic;

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
                Console.WriteLine("학생 로그인");
                return Ok(json);

            } else if (academic_connection.ExecuteScalar<int>(professor_exist_query, parameters) == 1) {

                string authCode = GenerateCode();

                var response = new AuthorizationCodeResponse { UserId = request.UserId, AuthorizationCode = authCode };
                string json = JsonSerializer.Serialize(response);
                Console.WriteLine("교수 로그인");
                return Ok(json);

            } else {
                if (Regex.IsMatch(request.UserId, @"^\d{8}$")) {
                    
                    var student_insert_query = "INSERT INTO Student (id, name, passwd) VALUES (@new_id, @new_name, 'qwerty');";
                    var insert_parameters = new DynamicParameters();
                    insert_parameters.Add("new_id", int.Parse(request.UserId));

                    string name = GenerateRandomKoreanName();
                    insert_parameters.Add("new_name", name);

                    Console.WriteLine("새로 추가 " + name);
                    academic_connection.Execute(student_insert_query, insert_parameters);

                    var central_connection = new NpgsqlConnection("Host=classdb.postgres.database.azure.com;Username=byungmeo;Password=Mju12345!#;Database=classdb");
                    var new_stu_query = "INSERT INTO Student(room_id, student_id, name) VALUES(@new_class, @new_id, @new_name);";
                    var insert_class_parameters = new DynamicParameters();
                    insert_class_parameters.Add("new_id", int.Parse(request.UserId));
                    insert_class_parameters.Add("new_name", name);

                    insert_class_parameters.Add("new_class", 1);
                    central_connection.Execute(new_stu_query, insert_class_parameters);

                    insert_class_parameters.Add("new_class", 10);
                    central_connection.Execute(new_stu_query, insert_class_parameters);

                    insert_class_parameters.Add("new_class", 31);
                    central_connection.Execute(new_stu_query, insert_class_parameters);

                    insert_class_parameters.Add("new_class", 32);
                    central_connection.Execute(new_stu_query, insert_class_parameters);

                    string authCode = GenerateCode();

                    var response = new AuthorizationCodeResponse { UserId = request.UserId, AuthorizationCode = authCode };
                    string json = JsonSerializer.Serialize(response);
                    Console.WriteLine("학생 로그인");
                    return Ok(json);

                } else {
                    Console.WriteLine("계정정보 없음");
                    return BadRequest();
                }
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

        private string GenerateRandomKoreanName() {
            Random random = new Random();
            StringBuilder sb = new StringBuilder();

            int initialConsonantCode = random.Next(0, 19) * 21 * 28; // 초성
            int middleVowelCode = random.Next(0, 20) * 28; // 중성
            int finalConsonantCode = random.Next(0, 28); // 종성

            char initialConsonant = (char)(0xAC00 + initialConsonantCode);
            char middleVowel = (char)(0xAC00 + middleVowelCode);
            char finalConsonant = (char)(0xAC00 + finalConsonantCode);

            sb.Append(initialConsonant);
            sb.Append(middleVowel);

            // 종성이 없는 경우 예외 처리
            if (finalConsonantCode != 0)
                sb.Append(finalConsonant);

            return sb.ToString();
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
            // JWT 토큰 생성
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

            // 데이터 저장
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