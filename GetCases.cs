using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    public class GetCases
    {
        private readonly ILogger _logger;

        public GetCases(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<GetCases>();
        }

        [Function("GetCases")]
        public async Task<HttpResponseData> Run(
            // Notice the Route = "cases". This creates the /api/cases URL!
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "cases")] HttpRequestData req,
            
            // This pulls the cases out of the database automatically
            [CosmosDBInput(
                databaseName: "ThreatIntelDb", 
                containerName: "cases", 
                Connection = "CosmosDbConnection", 
                SqlQuery = "SELECT * FROM c ORDER BY c._ts DESC")] IEnumerable<Case> activeCases)
        {
            _logger.LogInformation("Frontend dashboard requested active cases.");

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(activeCases);
            
            return response;
        }
    }
}