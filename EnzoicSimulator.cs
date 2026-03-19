using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace ThreatIntelPlatform
{
    public class EnzoicSimulator
    {
        private readonly ILogger _logger;
        private static readonly HttpClient _httpClient = new HttpClient();

        public EnzoicSimulator(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<EnzoicSimulator>();
        }

        // The CRON expression "*/45 * * * * *" means: Run automatically every 45 seconds!
        [Function("EnzoicLiveSimulator")]
        public async Task Run([TimerTrigger("*/45 * * * * *")] TimerInfo myTimer)
        {
            _logger.LogInformation("[PROACTIVE] Enzoic Simulator waking up to send dark web data...");

            // 1. Generate a random target
            var victims = new[] { "ceo@dillpay.com", "cfo@dillpay.com", "admin@dillpay.com" };
            var random = new Random();
            string selectedVictim = victims[random.Next(victims.Length)];

            // 2. Format it EXACTLY like Enzoic's real production API
            var payload = new
            {
                exposureID = "Breach_DarkWeb_2026",
                username = selectedVictim,
                plaintextPassword = $"HackedPass{random.Next(1000, 9999)}!"
            };

            string jsonPayload = JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            // 3. Add the exact Basic Auth password Enzoic uses
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("Authorization", "Basic ZGVtb19rZXk6ZGVtb19zZWNyZXQ=");

            // 4. Fire it at your local Webhook completely automatically
            try
            {
                var response = await _httpClient.PostAsync("http://localhost:7071/api/EnzoicWebhook", content);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation($"[PROACTIVE] Successfully routed {selectedVictim} to Enzoic Webhook.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"[PROACTIVE] Failed to route simulated webhook: {ex.Message}");
            }
        }
    }
}