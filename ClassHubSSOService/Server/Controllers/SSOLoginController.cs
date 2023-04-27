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
        [HttpPost] //�α��� POST��û
        public async Task<IActionResult> POST([FromBody] SSOLoginRequest request)
        {
            Console.WriteLine("[ID : " + request.UserId + " PW : " + request.Password + "]���� �α��� �õ��� �߽��ϴ�. \n���� ���� ������ �ش� ���������� �����մϴ�.");
            //���������� ID�� PW�� ����
            using HttpClient httpClient = new HttpClient();
            string apiUrl = "https://classhubsso.azurewebsites.net/SSOAuthorizarion";

            var content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json");
            HttpResponseMessage response = await httpClient.PostAsync(apiUrl, content);

            //���� �ڵ� ����
            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                AuthorizationCodeResponse data = JsonSerializer.Deserialize<AuthorizationCodeResponse>(json, options);

                Console.WriteLine("[" + JsonSerializer.Serialize(data) + "] ���� �ڵ带 �޾ҽ��ϴ�.");

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