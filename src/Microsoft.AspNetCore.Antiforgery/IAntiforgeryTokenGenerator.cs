// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Antiforgery
{
    /// <summary>
    /// Generates and validates antiforgery tokens.
    /// </summary>
    public interface IAntiforgeryTokenGenerator
    {
        /// <summary>
        /// Generates a new random cookie token.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/> associated with the current request.</param>
        /// <returns>An <see cref="AntiforgeryToken"/>.</returns>
        AntiforgeryToken GenerateCookieToken(HttpContext httpContext);

        // Given a cookie token, generates a corresponding request token.
        // The incoming cookie token must be valid.

        /// <summary>
        /// Generates a request token corresponding to <paramref name="cookieToken"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/> associated with the current request.</param>
        /// <param name="cookieToken">A valid cookie token.</param>
        /// <returns>An <see cref="AntiforgeryToken"/>.</returns>
        AntiforgeryToken GenerateRequestToken(HttpContext httpContext, AntiforgeryToken cookieToken);

        /// <summary>
        /// Attempts to validate a cookie token for the given <paramref name="httpContext"/>/
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/> associated with the current request.</param>
        /// <param name="cookieToken">A valid cookie token.</param>
        /// <returns><c>true</c> if the cookie token is valid, otherwise <c>false</c>.</returns>
        bool IsCookieTokenValid(HttpContext httpContext, AntiforgeryToken cookieToken);

        /// <summary>
        /// Attempts to validate a cookie and request token set for the given <paramref name="httpContext"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/> associated with the current request.</param>
        /// <param name="cookieToken">A cookie token.</param>
        /// <param name="requestToken">A request token.</param>
        /// <param name="message">
        /// Will be set to the validation message if the tokens are invalid, otherwise <c>null</c>.
        /// </param>
        /// <returns><c>true</c> if the tokens are valid, otherwise <c>false</c>.</returns>
        bool TryValidateTokenSet(
            HttpContext httpContext,
            AntiforgeryToken cookieToken,
            AntiforgeryToken requestToken,
            out string message);
    }
}