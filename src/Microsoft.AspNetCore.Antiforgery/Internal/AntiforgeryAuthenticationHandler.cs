// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication.Internal;

namespace Microsoft.AspNetCore.Antiforgery.Internal
{
    public class AntiforgeryAuthenticationHandler : IAuthenticationHandler
    {
        public AntiforgeryAuthenticationHandler(IAntiforgery antiforgery)
        {
            Antiforgery = antiforgery;
        }

        protected IAntiforgery Antiforgery { get; }

        public HttpContext HttpContext { get; private set; }

        public IAuthenticationHandler PriorHandler { get; private set; }

        public async Task InitializeAsync(HttpContext context)
        {
            HttpContext = context;

            var authentication = GetAuthenticationFeature(HttpContext);

            PriorHandler = authentication.Handler;
            authentication.Handler = this;

            if (authentication.User != null)
            {
                if (!await Antiforgery.IsRequestValidAsync(HttpContext))
                {
                    // Wipe out any existing principal if we can't validate this request.
                    authentication.User = null;
                    return;
                }
            }
        }

        /// <inheritdoc />
        public async Task AuthenticateAsync(AuthenticateContext context)
        {
            if (PriorHandler != null)
            {
                await PriorHandler.AuthenticateAsync(context);

                var authentication = GetAuthenticationFeature(HttpContext);
                if (context.Principal != null)
                {
                    try
                    {
                        await Antiforgery.ValidateRequestAsync(HttpContext, context.Principal);
                    }
                    catch (AntiforgeryValidationException ex)
                    {
                        context.Failed(ex);
                        return;
                    }
                }
            }
        }

        /// <inheritdoc />
        public Task ChallengeAsync(ChallengeContext context)
        {
            if (PriorHandler != null)
            {
                return PriorHandler.ChallengeAsync(context);
            }

            return TaskCache.CompletedTask;
        }

        /// <inheritdoc />
        public void GetDescriptions(DescribeSchemesContext context)
        {
            if (PriorHandler != null)
            {
                PriorHandler.GetDescriptions(context);
            }
        }

        /// <inheritdoc />
        public Task SignInAsync(SignInContext context)
        {
            if (PriorHandler != null)
            {
                return PriorHandler.SignInAsync(context);
            }

            return TaskCache.CompletedTask;
        }

        /// <inheritdoc />
        public Task SignOutAsync(SignOutContext context)
        {
            if (PriorHandler != null)
            {
                return PriorHandler.SignOutAsync(context);
            }

            return TaskCache.CompletedTask;
        }

        private static IHttpAuthenticationFeature GetAuthenticationFeature(HttpContext httpContext)
        {
            var authentication = httpContext.Features.Get<IHttpAuthenticationFeature>();
            if (authentication == null)
            {
                authentication = new HttpAuthenticationFeature();
                httpContext.Features.Set(authentication);
            }

            return authentication;
        }
    }
}
