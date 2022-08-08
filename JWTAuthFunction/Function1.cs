using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Collections.Specialized;
using Microsoft.Azure.WebJobs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JWTAuthFunction
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var certificateKV = Environment.GetEnvironmentVariable("CertificateFromKeyVault", EnvironmentVariableTarget.Process);

            var header = new { alg = "RS256" };
            var claimTemplate = new
            {
                iss = "3MVG9OjW2TAjFKUtXlyB_LCZdl9.7bvM3BVmbz5E1Bbi2EtwOsl5Nf.UpvDsxflILZDYrPUSzWG0toKtTEv8E",
                sub = "tsolakidis@uat.deloitte.gr",
                aud = "https://test.salesforce.com",
                exp = GetExpiryDate(),
                jti = Guid.NewGuid(),
            };

            // encoded header
            var headerSerialized = JsonConvert.SerializeObject(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = ToBase64UrlString(headerBytes);

            // encoded claim template
            var claimSerialized = JsonConvert.SerializeObject(claimTemplate);
            var claimBytes = Encoding.UTF8.GetBytes(claimSerialized);
            var claimEncoded = ToBase64UrlString(claimBytes);

            // input
            var input = headerEncoded + "." + claimEncoded;
            //var inputBytes = Encoding.UTF8.GetBytes(input);

            var privateKeyBytes = Convert.FromBase64String(certificateKV.ToString());
            //var certificate = new X509Certificate2(privateKeyBytes, string.Empty);
            //log.LogInformation("Certificate Loaded...");

            var cert = new X509Certificate2(privateKeyBytes, "W3lcome!",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            var signingCredentials = new X509SigningCredentials(cert, "RS256");
            var signature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
            var jwt = headerEncoded + "." + claimEncoded + "." + signature;
            log.LogInformation("JWT created and signed successfully!");

            var client = new WebClient
            {
                Encoding = Encoding.UTF8
            };
            var uri = "https://mydei--uat.sandbox.my.salesforce.com/services/oauth2/token";
            var content = new NameValueCollection
            {
                ["assertion"] = jwt,
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            };

            string response = Encoding.UTF8.GetString(client.UploadValues(uri, "POST", content));

            // returns access token
            var responseMessage = JsonConvert.DeserializeObject<dynamic>(response);


            return new OkObjectResult(responseMessage);
        }


        static int GetExpiryDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentUtcTime = DateTime.UtcNow;

            var exp = (int)currentUtcTime.AddMinutes(3).Subtract(utc0).TotalSeconds;

            return exp;
        }

        static string ToBase64UrlString(byte[] input)
        {
            return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
