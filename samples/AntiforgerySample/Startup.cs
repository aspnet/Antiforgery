// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNet.Antiforgery;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Features.Internal;
using Microsoft.AspNet.Http.Internal;
using Microsoft.AspNet.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.OptionsModel;
using Microsoft.Extensions.PlatformAbstractions;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;

namespace AntiforgerySample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRouting();
            
            // Angular's default header name for sending the XSRF token.
            services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

            services.AddSingleton<TodoRepository>();
        }

        public void Configure(IApplicationBuilder app, IAntiforgery antiforgery, IOptions<AntiforgeryOptions> options, TodoRepository repository)
        {
            app.Use(next => context =>
            {
                if (context.Request.Path == "/")
                {
                    // We can send the request token as a JavaScript-readable cookie, and Angular will use it by default.
                    var tokens = antiforgery.GetAndStoreTokens(context);
                    context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new CookieOptions() { HttpOnly = false });
                }

                return next(context);
            });

            app.UseDefaultFiles();
            app.UseStaticFiles();

            var routes = new RouteBuilder(app);

            routes.MapGet("api/items", (HttpContext context) =>
            {
                var items = repository.GetItems();
                return context.Response.WriteAsync(JsonConvert.SerializeObject(items));
            });

            routes.MapPost("api/items", async (HttpContext context) =>
            {
                // This will throw if the token is invalid.
                await antiforgery.ValidateRequestAsync(context);

                var serializer = new JsonSerializer();
                using (var reader = new JsonTextReader(new StreamReader(context.Request.Body)))
                {
                    var item = serializer.Deserialize<TodoItem>(reader);
                    repository.Add(item);
                }

                context.Response.StatusCode = 204;
            });

            app.UseRouter(routes.Build());
        }
    }
}
