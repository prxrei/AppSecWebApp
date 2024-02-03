using Microsoft.Extensions.Options;
using System.Net;
using Newtonsoft.Json;
using AppSecWebApp.Pages;
using AppSecWebApp.Model;
using AppSecWebApp.ViewModels;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using Microsoft.Extensions.Logging;

namespace AppSecWebApp.Model
{
    public class GoogleV3Captcha
    {
        private readonly IOptionsMonitor<CaptchaConfiguration> _configuration;
        private readonly ILogger<GoogleV3Captcha> _logger;
        public GoogleV3Captcha(IOptionsMonitor<CaptchaConfiguration> configuration, ILogger<GoogleV3Captcha> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }
        public async Task<bool> CheckToken(string token)
        {
            try
            {
                _logger.LogInformation($"SecretKey: {_configuration.CurrentValue.SecretKey}");
                var url = $"https://www.google.com/recaptcha/api/siteverify?secret={_configuration.CurrentValue.SecretKey}&response={token}";

                using(var client  = new HttpClient())
                {
                    var httpResponse = await client.GetAsync(url);
                    if (httpResponse.StatusCode != HttpStatusCode.OK) {
                        return false;
                    }
                    _logger.LogInformation($"httpResponse: {httpResponse}");

                    var responseStr = await httpResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"responseStr: {responseStr}");

                    var result = JsonConvert.DeserializeObject<GoogleV3CaptchaResponse>(responseStr);
                    _logger.LogInformation($"result: {result}");

                    return result.Success && result.Score >= 0.5;
                }
            }
            catch (Exception e)
            { 
                return false;
            }
        }
    }
}
