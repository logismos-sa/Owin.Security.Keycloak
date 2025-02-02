﻿using System;
using System.Runtime.CompilerServices;
using System.Web;

namespace Keycloak.IdentityModel.Utilities.Caching
{
    public abstract class Cache
    {
        protected readonly TimeSpan DefaultCacheLife = new TimeSpan(0, 70, 0); // 30 Minutes

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected System.Web.Caching.Cache GetCache()
        {
            return HttpRuntime.Cache;
        }
    }
}