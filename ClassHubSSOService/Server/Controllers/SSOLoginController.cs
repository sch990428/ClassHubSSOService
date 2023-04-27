using SSOAuthorizationServer.Shared;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using System;

namespace ClassHubSSO.Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SSOLoginController : ControllerBase
    {
        [HttpPost] //로그인 POST요청
        public async Task<IActionResult> POST([FromBody] SSOLoginRequest request)
        {
            Console.WriteLine("[ID : " + request.UserId + " PW : " + request.Password + "]에서 로그인 시도를 했습니다. \n이제 인증 서버로 해당 계정정보를 전송합니다.");
            //인증서버로 ID와 PW를 보냄
            using HttpClient httpClient = new HttpClient();
            string apiUrl = "https://classhubsso.azurewebsites.net/SSOAuthorizarion";

            var content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json");
            HttpResponseMessage response = await httpClient.PostAsync(apiUrl, content);

            //인증 코드 수령
            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                AuthorizationCodeResponse data = JsonSerializer.Deserialize<AuthorizationCodeResponse>(json, options);

                Console.WriteLine("[" + JsonSerializer.Serialize(data) + "] 인증 코드를 받았습니다.");

                if (Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out Uri redirectUri)
    && QueryHelpers.ParseQuery(redirectUri.Query).TryGetValue("redirect_uri", out var redirectUriValue))
                {
                    string redirectUrlWithAuthCode = $"{redirectUriValue}?id={data.UserId}&code={data.AuthorizationCode}";

                    return Ok(redirectUrlWithAuthCode);
                }
                return Ok();
            }
            else
            {
                return StatusCode((int)response.StatusCode);
            }
        }
    };
}