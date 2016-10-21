using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTDemo.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly SigningCredentials _signingCredentials;
        private readonly JsonSerializerSettings _serializerSettings;


        public AccountController()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("needtogetthisfromsomewheresafeandsecure"));
            _signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            _serializerSettings = new JsonSerializerSettings { Formatting = Formatting.Indented };
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult ValidUserWithSeriousClaimsLogin()
        {
            const string validUserWithSeriousClaims = "Valid User With Serious Claims";
            var claims = GetValidUserClaims(validUserWithSeriousClaims).ToList();

            claims.Add(new Claim(ClaimTypes.Country, "This is SPARTA!", ClaimValueTypes.String, Issuer));

            var claimsIdentity = new ClaimsIdentity("ValidUserWithSeriousClaimsIdentity");
            claimsIdentity.AddClaims(claims);
            return TokenResponse(claimsIdentity);

        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult ValidUserWithoutAnySeriousClaimsLogin()
        {
            const string validUserWithoutAnySeriousClaims = "Valid User Without Any Serious Claims";
            var claims = GetValidUserClaims(validUserWithoutAnySeriousClaims);

            var claimsIdentity = new ClaimsIdentity("ValidUserWithoutAnySeriousClaimsIdentity");
            claimsIdentity.AddClaims(claims);

            return TokenResponse(claimsIdentity);

        }


        [HttpPost]
        [AllowAnonymous]
        public IActionResult GenerateInvalidUserToken()
        {
            const string validUserWithoutAnySeriousClaims = "Token Signed with Invalid Crednetials";

            var claims = GetValidUserClaims(validUserWithoutAnySeriousClaims);
            var claimsIdentity = new ClaimsIdentity("TokenSignedWithInvalidCredentials");
            claimsIdentity.AddClaims(claims);

            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("someincorrectkey"));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            return TokenResponse(claimsIdentity, signingCredentials);
        }

        private IActionResult TokenResponse(ClaimsIdentity identity, SigningCredentials overridSigningCredentials = null)
        {
            var jwt = new JwtSecurityToken(
                issuer: Issuer,
                audience: Issuer,
                claims: identity.Claims,
                expires: DateTime.UtcNow.AddMinutes(10),
                signingCredentials: overridSigningCredentials ?? _signingCredentials
                );
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt
            };

            var json = JsonConvert.SerializeObject(response, _serializerSettings);
            return new OkObjectResult(json);
        }
        private static IEnumerable<Claim> GetValidUserClaims(string validUserName)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, validUserName, ClaimValueTypes.String, Issuer),
                new Claim(JwtRegisteredClaimNames.Jti, JtiGenerator, ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.Role, "ValidUsers", Issuer),
                new Claim(ClaimTypes.Name, validUserName)
            };
            return claims;

        }
        private static string Issuer => "http://localhost:16137/";
        private static string JtiGenerator => Guid.NewGuid().ToString();
    }
}
