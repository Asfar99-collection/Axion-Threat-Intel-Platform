using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    // A simplified output class since we no longer need to send an HTTP response back to a user
    public class AutomatedOutput
    {
        [CosmosDBOutput(databaseName: "ThreatIntelDb", containerName: "signals", Connection = "CosmosDbConnection")]
        public CanonicalSignal CosmosDocument { get; set; }

        [ServiceBusOutput("signals.incoming", Connection = "ServiceBusConnection")]
        public string ServiceBusMessage { get; set; }
    }

    public class DnsTwistScanner
    {
        private readonly ILogger _logger;

        public DnsTwistScanner(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<DnsTwistScanner>();
        }

        // The CRON expression "0 */1 * * * *" means: Run automatically every 1 minute!
        [Function("RunDailyDnsTwist")]
       public async Task<AutomatedOutput> Run([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer)
        {
            _logger.LogInformation($"[PROACTIVE SCAN] Waking up to hunt typosquats at: {DateTime.Now}");

            var typosquatCandidates = new List<string> { "example.com" }; // Simulated active domain
            CanonicalSignal threatSignal = null;

            foreach (var domain in typosquatCandidates)
            {
                _logger.LogInformation($"Actively probing: {domain}");
                int riskScore = 0;
                string snippetDetails = "";

                // 1. DNS PROBE
                try {
                    var ips = await Dns.GetHostAddressesAsync(domain);
                    riskScore += 40; 
                    snippetDetails += $"DNS Active. ";
                } catch { continue; } 

                // 2. HTTP PROBE
                try {
                    using var handler = new HttpClientHandler();
                    handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) => {
                        snippetDetails += $"TLS Cert: {cert.Subject}. "; return true;
                    };
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
                    var response = await client.GetAsync($"https://{domain}");
                    riskScore += 45; 
                } catch { }

                // 3. THREAT EVALUATION
                if (riskScore >= 80) 
                {
                    _logger.LogWarning($"High Risk Typosquat Found: {domain}!");
                    threatSignal = new CanonicalSignal
                    {
                        id = Guid.NewGuid().ToString(),
                        Source = "DNSTwist_Automated",
                        TenantId = "Demo_Client_001",
                        Type = "suspicious_domain",
                        Score = riskScore,
                        ReasonCodes = new List<string> { "Typosquatting_Active_Site" },
                        Iocs = new List<string> { $"SuspiciousDomain:{domain}" },
                        Snippet = snippetDetails,
                        Timestamp = DateTime.UtcNow
                    };
                    break; 
                }
            }

            if (threatSignal == null) return null;

            _logger.LogInformation("Scan complete. Routing threat to pipeline.");
            return new AutomatedOutput
            {
                CosmosDocument = threatSignal,
                ServiceBusMessage = JsonSerializer.Serialize(threatSignal)
            };
        }
    }
}