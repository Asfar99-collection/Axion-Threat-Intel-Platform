using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    public class IngestionOutput
    {
        [CosmosDBOutput(databaseName: "ThreatIntelDb", containerName: "signals", Connection = "CosmosDbConnection")]
        public CanonicalSignal CosmosDocument { get; set; }

        [ServiceBusOutput("signals.incoming", Connection = "ServiceBusConnection")]
        public string ServiceBusMessage { get; set; }

        [HttpResult] // Fixes the compiler warning
        public HttpResponseData HttpResponse { get; set; }
    }

    public class EnzoicWebhook
    {
        private readonly ILogger _logger;

        public EnzoicWebhook(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<EnzoicWebhook>();
        }

        [Function("EnzoicWebhook")]
        public async Task<IngestionOutput> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
        {
            _logger.LogInformation("Incoming REAL Enzoic webhook triggered.");

            // ==========================================
            // 1. REAL WORLD VALIDATION (Basic Auth)
            // ==========================================
            string expectedAuth = Environment.GetEnvironmentVariable("EnzoicSecret");
            
            if (!req.Headers.TryGetValues("Authorization", out var headerValues) || headerValues.First() != expectedAuth)
            {
                _logger.LogWarning("SECURITY ALERT: Invalid or missing Enzoic credentials. Connection refused.");
                var unauthorizedResponse = req.CreateResponse(HttpStatusCode.Unauthorized);
                return new IngestionOutput { HttpResponse = unauthorizedResponse };
            }

            // ==========================================
            // 2. PARSE THE REAL ENZOIC JSON
            // ==========================================
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            using JsonDocument incomingData = JsonDocument.Parse(requestBody);
            JsonElement root = incomingData.RootElement;

            // Enzoic's real API uses 'username' and 'exposureID'
            string compromisedEmail = root.TryGetProperty("username", out var emailNode) ? emailNode.GetString() : "unknown_email";
            string breachName = root.TryGetProperty("exposureID", out var breachNode) ? breachNode.GetString() : "unknown_breach";

            // ==========================================
            // 3. DEDUPLICATION LOGIC
            // ==========================================
            string rawIdString = $"{compromisedEmail}-{breachName}";
            byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawIdString));
            string deduplicationId = Convert.ToHexString(hashBytes).ToLower();

            // ==========================================
            // 4. PUSH TO SIGNAL PIPELINE
            // ==========================================
            var normalizedSignal = new CanonicalSignal
            {
                id = deduplicationId,
                Source = "Enzoic_Live",
                TenantId = "Demo_Client_001",
                Type = "credential_exposure",
                Score = 90,
                ReasonCodes = new List<string> { $"Breach:{breachName}" },
                Iocs = new List<string> { $"CompromisedEmail:{compromisedEmail}" },
                Snippet = requestBody.Length > 250 ? requestBody.Substring(0, 250) + "..." : requestBody,
                Timestamp = DateTime.UtcNow
            };

            // Enzoic's real API uses 'plaintextPassword'
            if (root.TryGetProperty("plaintextPassword", out JsonElement passwordElement))
            {
                normalizedSignal.Iocs.Add($"ExposedPassword:{passwordElement.GetString()}");
            }

            var successResponse = req.CreateResponse(HttpStatusCode.OK);
            await successResponse.WriteStringAsync("Real Enzoic Data received and processed!");

            return new IngestionOutput
            {
                CosmosDocument = normalizedSignal,
                ServiceBusMessage = JsonSerializer.Serialize(normalizedSignal),
                HttpResponse = successResponse
            };
        }
    }
}