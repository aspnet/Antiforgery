﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery.Internal;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Antiforgery
{
    /// <summary>
    /// A middleware implementation of antiforgery validation.
    /// </summary>
    public class AntiforgeryMiddleware
    {
        /// <summary>
        /// Creates a new <see cref="AntiforgeryMiddleware"/>.
        /// </summary>
        /// <param name="next">The <see cref="RequestDelegate"/> for the next middleware.</param>
        /// <param name="antiforgery">The <see cref="IAntiforgery"/>.</param>
        public AntiforgeryMiddleware(RequestDelegate next, IAntiforgery antiforgery)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (antiforgery == null)
            {
                throw new ArgumentNullException(nameof(antiforgery));
            }

            Next = next;
            Antiforgery = antiforgery;
        }

        /// <summary>
        /// Gets the <see cref="IAntiforgery"/>.
        /// </summary>
        protected IAntiforgery Antiforgery { get; }

        /// <summary>
        /// Gets the <see cref="RequestDelegate"/> for the next middleware.
        /// </summary>
        protected RequestDelegate Next { get; }

        /// <summary>
        /// Invokes the middleware for the given <paramref name="httpContext"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/> associated with the current request.</param>
        /// <returns>A <see cref="Task"/> which will be completed when execution of the middleware completes.</returns>
        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException(nameof(httpContext));
            }

            var handler = CreateHandler();
            await handler.InitializeAsync(httpContext);

            await Next(httpContext);
        }

        private AntiforgeryAuthenticationHandler CreateHandler()
        {
            return new AntiforgeryAuthenticationHandler(Antiforgery);
        }
    }
}
