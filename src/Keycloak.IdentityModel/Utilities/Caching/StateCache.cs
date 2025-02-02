﻿using System;
using System.Collections.Generic;

namespace Keycloak.IdentityModel.Utilities.Caching
{
    public class StateCache : Cache
    {
        private const string CachePrefix = "oidc_state_";
        private readonly log4net.ILog _logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);


        public string CreateState(Dictionary<string, object> stateData, TimeSpan? lifeTime = null)
        {
            if (lifeTime == null) lifeTime = DefaultCacheLife;

            // Generate state key
            var stateKey = CachePrefix + Guid.NewGuid().ToString("N");
            _logger.Debug($"Inserting new key in Cache {stateKey}");

            // Insert into cache
            GetCache().Insert(stateKey, stateData, null, System.Web.Caching.Cache.NoAbsoluteExpiration, lifeTime.Value);

            return stateKey;
        }

        public Dictionary<string, object> ReturnState(string stateKey)
        {
            return GetCache().Remove(stateKey) as Dictionary<string, object>;
        }
    }
}