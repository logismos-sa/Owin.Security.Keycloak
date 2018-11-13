using System;
using System.Globalization;

namespace KeycloakIdentityModel.Extensions
{
    internal static class DateTimeExtension
    {
        private static readonly string generalClaimsFormat = "MM/dd/yyyy HH:mm:ss";
        private static readonly string generalFormat = "yyyy-MM-ddTHH:mm:sszz00";
        private static readonly log4net.ILog Logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public static double ToUnixTimestamp(this DateTime dateTime)
        {
            return (dateTime - new DateTime(1970, 1, 1).ToLocalTime()).TotalSeconds;
        }

        public static DateTime ToDateTime(this double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            var dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

        public static DateTime ToDateTime(this long unixTimeStamp)
        {
            return ToDateTime((double) unixTimeStamp);
        }

        /// <summary>
        /// Parses date of format <see cref="generalClaimsFormat"/> to the general formatting <see cref="generalFormat"/>
        /// If an error occurs it returns null datetime object.
        /// </summary>
        /// <param name="dt">The date in format <see cref="generalClaimsFormat"/></param>
        /// <returns>A Datetime in format <see cref="generalFormat"/> or null</returns>
        public static DateTime? ParseClaimsDateToFormat(string dt)
        {
            try
            {
                string date = DateTime.ParseExact(dt, generalClaimsFormat,
                    CultureInfo.InvariantCulture).ToString(generalFormat);
                return DateTime.Parse(date);
            }
            catch (Exception ex)
            {
                Logger.Error($"Date {dt} could not be parsed to format {generalFormat}, returning null", ex);
                return null;
            }
        }
    }
}