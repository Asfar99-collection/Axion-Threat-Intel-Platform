using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    public class CertStreamScanner
    {
        private readonly ILogger _logger;

        public CertStreamScanner(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<CertStreamScanner>();
        }

        // Fires automatically every 1 minute
        [Function("CertStreamLiveScanner")]
        public async Task<AutomatedOutput> Run([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer)
        {
            _logger.LogInformation("[PROACTIVE] Connecting to CertStream Global Firehose...");
            
            // Simulate the delay of scanning global traffic
            await Task.Delay(2000); 

            // Simulate catching a hacker registering a fake domain for your client
            string targetBrand = "login";
            string[] maliciousExtensions = { "-secure-login.com", "-auth-update.net", ".support-portal.xyz" };
            var random = new Random();
            string maliciousDomain = $"{targetBrand}{maliciousExtensions[random.Next(maliciousExtensions.Length)]}";

            _logger.LogWarning($"🚨 [LIVE THREAT CAUGHT] Suspicious TLS certificate issued for: {maliciousDomain}");

            // Format the Canonical Signal exactly as the pipeline expects
            var threatSignal = new CanonicalSignal
            {
                id = Guid.NewGuid().ToString(),
                Source = "CertStream Global",
                TenantId = "Demo_Client_001",
                Type = "brand_impersonation",
                Score = 85,
                ReasonCodes = new List<string> { "Suspicious_TLS_Cert" },
                Iocs = new List<string> { $"SuspiciousDomain:{maliciousDomain}" },
                Snippet = $"Subject: CN={maliciousDomain}, O=Let's Encrypt (Simulated)",
                Timestamp = DateTime.UtcNow
            };

            // Drop it on the conveyor belt
            return new AutomatedOutput
            {
                CosmosDocument = threatSignal,
                ServiceBusMessage = JsonSerializer.Serialize(threatSignal)
            };
        }
    }
}