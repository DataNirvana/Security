using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MGL.Data.DataUtilities;
using MGL.Security.Email;
using MGL.DomainModel;
using DataNirvana.Database;

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    ///     This class records the Users location and is normally used when the user logs in, requests a password reset or actually
    ///     resets their password.
    ///     All the methods in this class should be threadsafe so that they can be called from e.g. a usercontrol without impacting on the user experience too much
    ///     This is necessary as the GetLocationByIPAddress and GetLocationByGeocode wrap chunky SQL queries ...
    /// </summary>
    public class UserLocation {

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The configuration info with the location of the logging database table (Security_Users_Location)
        /// </summary>
        ConfigurationInfo ciDest = null;

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The configuration info with the location of the IP to City lookup database table and the list of cities, admin1, admin2 and countries from geonames
        /// </summary>
        ConfigurationInfo ciSrc = null;

        string appName = "";
        public static string LocationDBTN = "Security_Users_Location";

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The source config info contains the IP to City lookup and the list of cities;
        ///     the destination config points to the database with the Security_Users_Location table in it
        /// </summary>
        public UserLocation(ConfigurationInfo ciSrc, ConfigurationInfo ciDest, string applicationName) {
            this.ciDest = ciDest;
            this.ciSrc = ciSrc;
            this.appName = applicationName;

//            IPAddressHelper.Test();
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Will use one of the free databases to lookup our IP address and extract the location info
        ///     Admin1 is typically a province (e.g. Gauteng or Sindh) or a sub-country (e.g. England)
        ///     See this mysql reference for an explanation of how the sql works:
        ///     https://dev.mysql.com/doc/refman/5.7/en/miscellaneous-functions.html
        /// </summary>
        public bool GetLocationByIPAddress( string ipAddress, out string countryCode, out string country, out string admin1, out string city ) {
            bool success = false;

            city = admin1 = country = countryCode = "";
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciSrc);

                /*
                 * MySQL has this super useful query called INET_ATON
                    SELECT * FROM IP_City_Lookup WHERE
	                    (IP_From BETWEEN 3310027880 AND 3310327880
                        OR IP_To BETWEEN 3310027880 AND 3310327880)
                    AND (INET_ATON("197.76.139.8") BETWEEN IP_From AND IP_To);
                 *
                 * SELECT * FROM IP_City_Lookup WHERE (IP_From BETWEEN 3310117880 AND 3310137880 OR IP_To BETWEEN 3310117880 AND 3310137880)
                    AND IP_From <= 3310127880 AND IP_To >= 3310127880;
                 *
                 * For example, my local google.com is at 64.233.187.99. That's equivalent to:
                64*2^24 + 233*2^16 + 187*2^8 + 99
                = 1089059683
                */
                long ip = IPAddressHelper.ParseIP4(ipAddress);
                // an IP of zero is dangerous as it catches Los Angeles etc.
                if (ip > 0) {
                    // the IP to City database contains about 6 million records, therefore to optimise the query we want to try to box it off
                    // so we start small and increase exponentially until the fourth query is open
                    // An open query does take about 40 seconds though while the two most tightly boxed run almost instantaneously
                    // There for this might be better threaded ... to avoid the hit on the UI
                    // To recap, the 4th range is 256, the third is 65k and the second is 16 million or 65k from e.g. 1.1.1.1 to 1.2.1.1.
                    long[] searchRanges = new long[] { 10000, 100000, 1000000, long.MaxValue };

                    foreach (long searchRange in searchRanges) {

                        long min = ((ip - searchRange) < 0) ? 0 : (ip - searchRange);
                        long max = ip + searchRange;

                        // lets get our SQL on
                        StringBuilder sql = new StringBuilder();
                        sql.Append("SELECT Country_Code, Province, City FROM IP_City_Lookup WHERE ");
                        sql.Append("( IP_From BETWEEN " + min + " AND " + max);
                        sql.Append(" OR IP_To BETWEEN " + min + " AND " + max + ")");
                        sql.Append(" AND IP_From <= " + ip + " AND IP_To >= " + ip + ";");

                        string[] row = dbInfo.ReadLine(sql.ToString());
                        if (row != null && row.Length == 3) {
                            countryCode = row[0];
                            admin1 = row[1];
                            city = row[2];
                            success = true;
                            break;
                        }
                    }

                    // Lastly, lets get the country name - the countryCode is a two char iso code (e.g. GB for Blighty or PK for Pakistan)
                    success = success & GetNameCountry(countryCode, out country);
                } else {

                    success = true;
                    // probably an IP v6 address was supplied, which are not currently supported...
                }

            } catch (Exception ex) {
                Logger.LogError(6, "UserLocation - Problem finding the location information using the IPAddress: "
                   + ipAddress
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Will use the city database to lookup the nearest location info
        /// </summary>
        public bool GetLocationByGeocode(double latitude, double longitude, out string countryCode, out string country, out string admin1, out string admin2, out string city) {
            bool success = false;

            city = admin1 = admin2 = country = countryCode = "";
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciSrc);

                /*
                 * Magic multiplier - 6371  is KM and 3959 is miles
                 * We want to be a bit loose on the query at the expense of a bit of efficiency -
                 * We are using a bounding box in the query as the first part of the where clause to be as efficient as possible
                 * So limit the bounding box to be +1 one degree which is about 100km roughly and also put in a distance limiter on
                 * the line of sight part of the query
                 *
                    Select Geoname_ID, Name_Ascii, longitude, latitude,
                        ( 6371 * acos( cos( radians(50.81936) )
                            * cos( radians( latitude ) )
                            * cos( radians( longitude ) - radians(-1.57303) )
                            + sin( radians(50.81936) )
                            * sin( radians( latitude ) ) ) ) AS distance
                    from Geonames_Cities_1000
                    where
                    longitude between -2.57303 and -0.57303
                    and latitude between 49.81936 and 51.81936
                    having distance < 100
                    ORDER BY distance
                    LIMIT 1;
                 *
                 * */

                //  We are searching within 100km - not particularly fast, but it is a good all encompassing distance!
                double bBoxRadius = 1.0; // 1 whole degree
                // server is not as fast at processing, so lets make this a bit tigher
                //double bBoxRadius = 0.1;

                double minX = longitude - bBoxRadius;
                double maxX = longitude + bBoxRadius;
                double minY = latitude - bBoxRadius;
                double maxY = latitude + bBoxRadius;

                StringBuilder sql = new StringBuilder();
                sql.Append("Select Country_Code, Admin_1, Admin_2, Name_Original, ");
                sql.Append(@"( 6371 * acos( cos( radians("+latitude+@") )
                            * cos( radians( latitude ) )
                            * cos( radians( longitude ) - radians("+longitude+@") )
                            + sin( radians("+latitude+@") )
                            * sin( radians( latitude ) ) ) ) AS distance ");
                sql.Append(" from Geonames_Cities_1000 where ");
                sql.Append(" longitude between "+minX+" and "+maxX);
                sql.Append(" and latitude between "+minY+" and "+maxY);
                sql.Append(" having distance < 100");
                sql.Append(" ORDER BY distance");
                sql.Append(" LIMIT 1;");

                string[] row = dbInfo.ReadLine(sql.ToString());
                if (row != null && row.Length > 0) {
                    countryCode = row[0];
                    success = GetNameCountry(countryCode, out country);
                    success = success & GetNameAdmin1(countryCode, row[ 1 ], out admin1);
                    success = success & GetNameAdmin2(countryCode, row[ 1 ], row[2], out admin2);
                    city = row[3];
                }

            } catch (Exception ex) {
                Logger.LogError(6, "UserLocation - Problem finding the location information using the geocode - Longitude: "
                   + longitude
                   + " and Latitude: "+ latitude
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Will use one of the free databases to lookup our IP address and extract the location info
        ///     The countryCode is the two character code e.g. "ZA" for South Aftrica
        /// </summary>
        public bool GetNameCountry(string countryCode, out string country) {
            bool success = false;

            country = "";
            DatabaseWrapper dbInfo = null;

            try {

                dbInfo = new DatabaseWrapper(ciSrc);

                StringBuilder sql = new StringBuilder();
                sql.Append("SELECT Country FROM Geonames_Countries WHERE");
                sql.Append(" ISO=" + DataUtilities.DatabaseifyString(countryCode));
                sql.Append(";");

                List<string> strList = dbInfo.GetStringList(sql.ToString());

                if (strList != null && strList.Count > 0) {
                    country = strList[0];
                    success = true;
                } else {
                    Logger.LogError(3, "UserLocation - Did not find a Country name using country code: "
                        + countryCode
                        + ".");
                }

            } catch (Exception ex) {
                Logger.LogError(5, "UserLocation - Problem looking up the country name using country code: "
                    + countryCode
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Will use one of the free databases to lookup our IP address and extract the location info
        ///     Admin1 is typically a province (e.g. Gauteng or Sindh) or a sub-country (e.g. England)
        /// </summary>
        public bool GetNameAdmin1(string countryCode, string admin1Code, out string admin1) {
            bool success = false;

            admin1 = "";
            DatabaseWrapper dbInfo = null;

            try {

                string admin1CodeConcat = countryCode + "." + admin1Code;

                dbInfo = new DatabaseWrapper(ciSrc);

                StringBuilder sql = new StringBuilder();
                sql.Append("SELECT Name_Original FROM Geonames_Admin1 WHERE");
                sql.Append(" ID=" + DataUtilities.DatabaseifyString( admin1CodeConcat));
                sql.Append(";");

                List<string> strList = dbInfo.GetStringList(sql.ToString());

                if (strList != null && strList.Count > 0) {
                    admin1 = strList[0];
                    success = true;
                } else {
                    Logger.LogError(3, "UserLocation - Did not find an Admin1 name using country code: "
                        + countryCode
                        + " and admin1: " + admin1Code
                        + ".");
                }

            } catch (Exception ex) {
                Logger.LogError(5, "UserLocation - Problem looking up the admin1 name using country code: "
                    + countryCode
                    + " and admin1: " + admin1Code
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Will use one of the free databases to lookup our IP address and extract the location info
        ///     Admin2 is typically a district or county (e.g. Peshawar or Hampshire)
        /// </summary>
        public bool GetNameAdmin2(string countryCode, string admin1Code, string admin2Code, out string admin2) {
            bool success = false;

            admin2 = "";
            DatabaseWrapper dbInfo = null;

            try {

                // if the admin1Code or countryCode are null or empty this is reasonably serious.  With the admin2Code we can be a bit more forgiving
                // so, simply dont bother to check if it is null or empty
                if (string.IsNullOrEmpty(admin2Code) == true) {
                    success = true;
                } else {

                    string admin2CodeConcat = countryCode + "." + admin1Code + "." + admin2Code;

                    dbInfo = new DatabaseWrapper(ciSrc);

                    StringBuilder sql = new StringBuilder();
                    sql.Append("SELECT Name_Original FROM Geonames_Admin2 WHERE");
                    sql.Append(" ID=" + DataUtilities.DatabaseifyString(admin2CodeConcat));
                    sql.Append(";");

                    List<string> strList = dbInfo.GetStringList(sql.ToString());

                    if (strList != null && strList.Count > 0) {
                        admin2 = strList[0];
                        success = true;
                    } else {
                        Logger.LogError(3, "UserLocation - Did not find an Admin2 name using country code: "
                            + countryCode
                            + ", admin1: " + admin1Code
                            + " and admin2: " + admin2Code
                            + ".");
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "UserLocation - Problem looking up the admin2 name using country code: "
                    +countryCode
                    +", admin1: "+admin1Code
                    +" and admin2: "+admin2Code
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The computer ID is a GUID that is stored in the clients localstorage (still browser specific) and helps us to identify different computers that a user logs into
        ///     Returns whether or not the process completed successfully
        ///     pageRequested - 1=Login, 2=PasswordRequestReset 3=PasswordReset, 4=Admin and 5=proGresExport
        ///     4 and 5 are deprecated as they dont really show that much and 5 has no postbacks!
        ///     pageViewSuccessful - true if the view was successful e.g. the user managed to login
        /// </summary>
        public bool LogUserLocation(MGUser u, string computerID, int timezoneOffset, string city, string province, string country, string countryCode,
            double latitude, double longitude, string ipAddress, string browser, int pageRequested, bool pageViewSuccessful ) {

            bool success = false;
            int userID = 0;

            try {
                userID = (u == null || u.ID == Int32.MaxValue) ? 0 : u.ID;

                int locationID = 0;
                bool isNewLocation = IsNewLocation(userID, computerID, timezoneOffset, city, province, countryCode, ipAddress, browser, out locationID);
                DateTime lastLoginDate = DateTime.Now;

                if (isNewLocation == true) {

                    success = EmailUserWarning(u, computerID, timezoneOffset, city, province, country, countryCode, latitude, longitude, ipAddress, browser, lastLoginDate, pageViewSuccessful, pageRequested);
                    success = success & InsertLocation(userID, computerID, timezoneOffset, city, province, country, countryCode,
                        latitude, longitude, ipAddress, browser, lastLoginDate, pageRequested, pageViewSuccessful);
                } else {
                    success = UpdateLocation(locationID, userID, computerID, timezoneOffset, city, province, country, countryCode,
                        latitude, longitude, ipAddress, browser, lastLoginDate, pageRequested, pageViewSuccessful);
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Problem logging the users location with the following parameters; userID:" + userID
                    + " computerID:" + computerID
                    + " timezoneOffset:" + timezoneOffset
                    + " city:" + city
                    + " province:" + province
                    + " countryCode:" + countryCode
                    + " ipAddress:" + ipAddress
                    + " pageRequested:" + pageRequested
                    + ".  Check it out:" + ex.ToString());
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returns true if the computerID, timezoneOffset, city, province, countryCode or ipAddress does not already exist for a given user
        ///     If the location does exist already, the method will return false, and the location ID will passed using the out parameter
        ///     This makes it easy to then run the update on this info
        /// </summary>
        public bool IsNewLocation(int userID, string computerID, int timezoneOffset, string city, string province, string countryCode, string ipAddress, string browser, out int locationID) {

            bool isNew = false;
            DatabaseWrapper dbInfo = null;
            locationID = 0;

            try {
                dbInfo = new DatabaseWrapper(ciDest);

                // 31-Dec-2015 - modified this to also search for null computer_IDs, browsers and IP_Addresses which have occurred on one specific computer ...
                // so may crop up again in the future.  This caused the code to not find the location ID and pass this back to the IncrementViewCount code in the InsertLocation method ...
                StringBuilder sql = new StringBuilder();
                sql.Append("SELECT ID FROM " + LocationDBTN + " WHERE");
                sql.Append(" User_ID="                           +userID);
                sql.Append(" AND Computer_ID"          + ((string.IsNullOrEmpty(computerID)) ? " IS NULL" : "=" + DataUtilities.DatabaseifyString(computerID)));
                sql.Append(" AND Country_Code"          + ((string.IsNullOrEmpty(countryCode)) ? " IS NULL" : "="+ DataUtilities.DatabaseifyString(countryCode)));
                sql.Append(" AND Timezone_Offset=" + timezoneOffset);
                sql.Append(" AND City" +                   ((string.IsNullOrEmpty(city)) ? " IS NULL" : "="+ DataUtilities.DatabaseifyString(city)));
                sql.Append(" AND Province" +               ((string.IsNullOrEmpty(province)) ? " IS NULL" : "=" + DataUtilities.DatabaseifyString(province)));
                sql.Append(" AND IP_Address" + ((string.IsNullOrEmpty(ipAddress)) ? " IS NULL" : "=" + DataUtilities.DatabaseifyString(ipAddress)));
                sql.Append(" AND Browser" + ((string.IsNullOrEmpty(browser)) ? " IS NULL" : "=" + DataUtilities.DatabaseifyString(browser)));
                sql.Append(";");

                List<int> idList = dbInfo.GetIntegerList(sql.ToString());

                if (idList != null && idList.Count > 0) {
                    locationID = idList[0];
                } else {
                    isNew = true;
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Problem checking whether this is a new location or not with the following parameters; userID:" + userID
                    + " computerID:" + computerID
                    + " timezoneOffset:" + timezoneOffset
                    + " city:" + city
                    + " province:" + province
                    + " countryCode:" + countryCode
                    + " ipAddress:" + ipAddress
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return isNew;
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returns true if the computerCode or the ipAddress does not already exist for a given user
        ///     The computerCode could be refreshed if the user cleans out all the local data.
        ///     The IP address might change if the user's IP Address is dynamic
        ///     But if both have changed, this is probably a new location ...
        /// </summary>
        public bool IsNewLocation(int userID, string computerID, string ipAddress) {

            bool isNew = false;
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciDest);

                StringBuilder sql = new StringBuilder();
                sql.Append("SELECT ID FROM "+LocationDBTN+" WHERE");
                sql.Append(" User_ID=" + userID);
                sql.Append(" AND (Computer_ID=" + DataUtilities.DatabaseifyString(computerID));
                sql.Append(" OR IP_Address=" + DataUtilities.DatabaseifyString(ipAddress) + ")");
                sql.Append(";");

                List<int> idList = dbInfo.GetIntegerList(sql.ToString());

                if (idList != null && idList.Count > 0) {
                    // Do nothing
                } else {
                    isNew = true;
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Problem checking whether this is a new location or not with the following parameters; userID:" + userID
                    + " computerID:" + computerID
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return isNew;
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returns true if the countryCode does not already exist for a given user.  Only searches if the given country code is NOT empty or null.
        /// </summary>
        public bool IsNewLocation(int userID, string countryCode) {

            bool isNew = false;
            DatabaseWrapper dbInfo = null;

            try {

                if (string.IsNullOrEmpty(countryCode) == false) {

                    dbInfo = new DatabaseWrapper(ciDest);

                    StringBuilder sql = new StringBuilder();
                    sql.Append("SELECT ID FROM " + LocationDBTN + " WHERE");
                    sql.Append(" User_ID=" + userID);
//                    sql.Append(" AND Country_Code" + ((countryCode == null) ? " IS NULL" : "=" + DataUtilities.DatabaseifyString(countryCode)));
                    sql.Append(" AND Country_Code=" + DataUtilities.DatabaseifyString(countryCode));
                    sql.Append(";");

                    List<int> idList = dbInfo.GetIntegerList(sql.ToString());

                    if (idList != null && idList.Count > 0) {
                        // Do nothing
                    } else {
                        isNew = true;
                    }
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Problem checking whether this is a new location or not with the following parameters; userID:" + userID
                    + " countryCode:" + countryCode
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return isNew;
        }



        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returns true if the computerID, timezoneOffset, city, province, countryCode or ipAddress does not already exist for a given user
        ///     If the location does exist already, the method will return false, and the location ID will passed using the out parameter
        ///     This makes it easy to then run the update on this info
        /// </summary>
        private bool InsertLocation(int userID, string computerID, int timezoneOffset, string city, string province, string country, string countryCode,
            double latitude, double longitude, string ipAddress, string browser, DateTime lastLoginDate, int pageRequested, bool pageViewSuccessful) {

            bool success = false;
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciDest);


                StringBuilder sql = new StringBuilder();
                sql.Append("INSERT INTO "+LocationDBTN+" (");
                sql.Append(" User_ID, Computer_ID, Timezone_Offset, City, Province, Country, Country_Code, Latitude, Longitude, IP_Address, Browser,");
                sql.Append(" Last_Login_Date, Is_Active ");
                sql.Append(") VALUES (");

                sql.Append("  " + userID);
                sql.Append(", " + DataUtilities.DatabaseifyString(computerID));
                sql.Append(", " + timezoneOffset);
                sql.Append(", " + DataUtilities.DatabaseifyString(city));
                sql.Append(", " + DataUtilities.DatabaseifyString(province));
                sql.Append(", " + DataUtilities.DatabaseifyString(country));
                sql.Append(", " + DataUtilities.DatabaseifyString(countryCode));
                sql.Append(", " + latitude);
                sql.Append(", " + longitude);
                sql.Append(", " + DataUtilities.DatabaseifyString(ipAddress));
                sql.Append(", " + DataUtilities.DatabaseifyString(browser));
                // Log when this happened
                sql.Append(", " + DataUtilities.DatabaseifyString(DateTimeInformation.FormatDatabaseDate(lastLoginDate, true, true)));
                // Set the is_active to 1
                sql.Append(", 1");

                sql.Append(");");

                int numMods = dbInfo.ExecuteSQL(sql.ToString(), ref success);

                if (success == false || numMods == 0) {
                    Logger.LogError(7, "User Location - Insert for userID " + userID + " FAILED with this sql: " + sql.ToString());
                } else {
                    // Increment the number of logins, but first we need to get the ID of the newly inserted record
                    int locationID = 0;
                    IsNewLocation( userID, computerID, timezoneOffset, city, province, countryCode, ipAddress, browser, out locationID);
                    // 31-Dec-2015 - If the LocationID is 0, then we have a possible problem with the IsNewLocation method - so if this occurs, lets spit out all the info and see what comes up
                    if (locationID == 0) {
                        success = false;
                        Logger.LogError(105, "Probable (weird) error with the IsNewLocation method - we have just inserted the following info, but then IsNewLocation did not return a valid locationID - purlease investigate ("
                            +"UserID:"+userID
                            +", ComputerID:"+computerID
                            +", TimeZoneOffset:"+timezoneOffset
                            +", City:"+city
                            +"Province:"+province
                            +"CountryCode:"+countryCode
                            +"IPAddress:"+ipAddress
                            +"Browser:"+browser+")");
                    } else {
                        success = IncrementViewCount(locationID, pageRequested, pageViewSuccessful);
                    }
                }

            } catch (Exception ex) {
                Logger.LogError(7, "User Location - Problem inserting the new location with the following parameters; userID:" + userID
                    + " computerID:" + computerID
                    + " timezoneOffset:" + timezoneOffset
                    + " city:" + city
                    + " province:" + province
                    + " countryCode:" + countryCode
                    + " ipAddress:" + ipAddress
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returns true if the computerID, timezoneOffset, city, province, countryCode or ipAddress does not already exist for a given user
        ///     If the location does exist already, the method will return false, and the location ID will passed using the out parameter
        ///     This makes it easy to then run the update on this info
        /// </summary>
        private bool UpdateLocation(int locationID, int userID, string computerID, int timezoneOffset, string city, string province, string country, string countryCode,
            double latitude, double longitude, string ipAddress, string browser, DateTime lastLoginDate, int pageRequested, bool pageViewSuccessful) {

            bool success = false;
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciDest);

                StringBuilder sql = new StringBuilder();
                sql.Append("UPDATE "+LocationDBTN+" SET ");

                sql.Append("  User_ID=" + userID);
                sql.Append(", Computer_ID=" + DataUtilities.DatabaseifyString(computerID));
                sql.Append(", Timezone_Offset=" + timezoneOffset);
                sql.Append(", City=" + DataUtilities.DatabaseifyString(city));
                sql.Append(", Province=" + DataUtilities.DatabaseifyString(province));
                sql.Append(", Country=" + DataUtilities.DatabaseifyString(country));
                sql.Append(", Country_Code=" + DataUtilities.DatabaseifyString(countryCode));
                sql.Append(", Latitude=" + latitude);
                sql.Append(", Longitude=" + longitude);
                sql.Append(", IP_Address=" + DataUtilities.DatabaseifyString(ipAddress));
                sql.Append(", Browser=" + DataUtilities.DatabaseifyString(browser));
                // Log when this happened
                sql.Append(", Last_Login_Date=" + DataUtilities.DatabaseifyString(DateTimeInformation.FormatDatabaseDate(lastLoginDate, true, true)));
                // Set the is_active to 1
                sql.Append(", Is_Active=1");

                sql.Append(" WHERE ID="+locationID+";");

                int numMods = dbInfo.ExecuteSQL(sql.ToString(), ref success);

                if (success == false || numMods == 0) {
                    Logger.LogError(7, "User Location - Update for userID " + userID + " and row ID " + locationID + " FAILED with this sql: " + sql.ToString());
                } else {
                    // Increment the number of logins, but first we need to get the ID of the newly inserted record
                    success = IncrementViewCount(locationID, pageRequested, pageViewSuccessful);
                }

            } catch (Exception ex) {
                Logger.LogError(7, "User Location - Problem updating a location with the following parameters; userID:" + userID
                    + " computerID:" + computerID
                    + " timezoneOffset:" + timezoneOffset
                    + " city:" + city
                    + " province:" + province
                    + " countryCode:" + countryCode
                    + " ipAddress:" + ipAddress
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Increments the number of views relating to the specific page type
        ///     pageRequested - 1=Login, 2=PasswordRequestReset 3=PasswordReset, 4=Admin and 5=proGresExport
        ///     pageViewSuccessful - true if the view was successful e.g. the user managed to login
        /// </summary>
        private bool IncrementViewCount(int locationID, int pageRequested, bool pageViewSuccessful) {

            bool success = false;
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciDest);

                // Let's try to semi-automate this - if the summary column does not exist e.g. due to additional page types, lets just add it as a one time operation here ...
                if ( dbInfo.ColumnExists( LocationDBTN, "Num_Views_"+pageRequested ) == false ) {
                    dbInfo.AddColumn(LocationDBTN, "Num_Views_" + pageRequested, "tinyint", "0");
                }

                // Now lets append the summary count info
                StringBuilder sql = new StringBuilder();
                sql.Append("UPDATE "+LocationDBTN+" SET ");
                sql.Append(" Num_Views_Total=Num_Views_Total+1");
                if ( pageViewSuccessful == false ) {
                    sql.Append(", Num_Views_Failed=Num_Views_Failed+1");
                }
                sql.Append(", Num_Views_" + pageRequested + "=Num_Views_" + pageRequested + "+1");

                sql.Append(" WHERE ID="+locationID+";");

                int numMods = dbInfo.ExecuteSQL(sql.ToString(), ref success);

                if (success == false || numMods == 0) {
                    Logger.LogError(7, "User Location - IncrementViewCount for ID " + locationID + " FAILED with this sql: " + sql.ToString());
                }

            } catch (Exception ex) {
                Logger.LogError(7, "User Location - Problem incrementing the view count for location ID:" + locationID
                    + " pageRequested:" + pageRequested
                    + " pageViewSuccessful:" + pageViewSuccessful
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Emails as friendly warning / confirmation email to the user if one of the following "key" parameters has changed:
        ///     computerID and / or the IP_Address OR the countryCode
        ///     Note that as this method calls Authorisation.GetUser it is not threadsafe - 1-Dec-2015 - amended so it is now threadsafe
        ///     and the user info is passed into the method
        /// </summary>
        private bool EmailUserWarning(MGUser u, string computerID, int timezoneOffset, string city, string province, string country, string countryCode,
            double latitude, double longitude, string ipAddress, string browser, DateTime lastLoginDate, bool loginActionSuccessful, int pageRequested) {

            bool success = true; // innocent until proven guilty
            int userID = 0;

            try {
                // This is barely an error, as it could occur quite frequently, so lets just tamp the importance right down (8-Feb-2016 - degraded to a warning)
                if (u == null || u.ID == 0 || u.ID == Int32.MaxValue) {
                    Logger.LogWarning("104 - User Location - problem sending the email warning on a new computer or location as the given user credentials were null!  "
                        + " The countryCode " + countryCode + " and computerID " + computerID + " and IPAddress " + ipAddress + " and Browser " + browser
                        + " and pageRequested "+pageRequested+".  Have a look at why this has occurred.");
                } else {

                    userID = u.ID;

                    bool isNewComputer = (IsNewLocation(userID, computerID, ipAddress) == true);
                    bool isNewCountry = (IsNewLocation(userID, countryCode) == true);

                    if (isNewComputer == true || isNewCountry == true) {
                        // ok so we need to warn the user, so we need to send an email.  And of course in the email we need to be friendly and say who they are!
                        StringBuilder uName = SecureStringWrapper.Decrypt(u.FirstName);
                        StringBuilder uEmail = SecureStringWrapper.Decrypt(u.Email);

                        // write an email here
                        StringBuilder bodyText = new StringBuilder();
                        bodyText.Append("<p style='font-family: Trebuchet MS;'>");
                        bodyText.Append("Hi " + uName + ", <br /><br />");

                        if (loginActionSuccessful == true) {
                            bodyText.Append("You visited " + appName );
                        } else {
                            bodyText.Append("An unsuccessful attempt to log into " + appName + " was made ");
                        }
                        bodyText.Append(" today at " + DateTimeInformation.PrettyDateTimeFormat(lastLoginDate, timezoneOffset));

                        if (isNewComputer == true && isNewCountry == true) {
                            bodyText.Append(" on a new computer and from a new location. ");

                        } else if (isNewCountry == true) {
                            bodyText.Append(" from a new location. ");

                        } else if (isNewComputer == true) {
                            bodyText.Append(" on a new computer. ");
                        }

                        bodyText.Append("<br/><br/>If this was you, all is well.  If it wasn't please alert your " + appName + " web team <i>immediately</i> (by replying to this email).");
                        bodyText.Append("<br/><br/>The computer's IP address is: " + ipAddress );

                        if (string.IsNullOrEmpty(city) == false) {
                            bodyText.Append(" and the new location is: ");
                            bodyText.Append(city + ", " + province + ", " + country + ".");
                        }

                        bodyText.Append("<br/><br/>");
                        bodyText.Append("Cheers, <br />The " + appName + " support team");
                        bodyText.Append("<br /><br /></p>");

                        // And send the email ...
                        success = MGLSecureEmailer.SendEmail(uEmail, uName,
                            Authorisation.ApplicationName + " - New computer / location", bodyText.ToString(),
                            "", null, null, null, null, 0, MGLSecureEmailer.EnableSSL);

                    }

                    if (success == false) {
                        Logger.LogError(7, "User Location - problem sending the email warning on a new computer or location to userID " + userID
                            + " with countryCode " + countryCode + " and computerID " + computerID + " and IPAddress " + ipAddress
                            + " and pageRequested "+pageRequested+ ".  It has probably occurred as the email failed to send successfully.");
                    }
                }

            } catch (Exception ex) {
                Logger.LogError(7, "User Location - Problem sending the email warning on a new computer or location to userID:" + userID
                    + " computerID:" + computerID
                    + " timezoneOffset:" + timezoneOffset
                    + " city:" + city
                    + " province:" + province
                    + " countryCode:" + countryCode
                    + " ipAddress:" + ipAddress
                    + " and pageRequested " + pageRequested
                    + ".  Check it out:" + ex.ToString());

            }

            return success;
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Builds a simple HTML table summarising the locations from which a user has accessed the application
        ///     Returns true if the method ran successfully (no errors)
        /// </summary>
        public bool BuildLocationSummary(int userID, out StringBuilder html) {

            bool success = false;
            html = new StringBuilder();
            DatabaseWrapper dbInfo = null;

            try {
                dbInfo = new DatabaseWrapper(ciDest);

                // Now lets append the summary count info
                StringBuilder sql = new StringBuilder();
                sql.Append("SELECT Computer_ID, IP_Address, Browser, Timezone_Offset, City, Province, Country, Num_Views_Total, Num_Views_Failed, Last_Login_Date ");
                sql.Append("FROM " + LocationDBTN + " ");
                sql.Append("WHERE User_ID=" + userID + " ");
                sql.Append("ORDER BY Computer_ID, Last_Login_Date DESC;");

                List<string[]> data = dbInfo.GetDataList(sql.ToString());

                if (data == null || data.Count == 0) {
                    Logger.LogError(7, "User Location - BuildLocationSummary - no data found for user ID " + userID + ".  This should be unusual as this is logged every user login.  SQL: " + sql.ToString());
                } else {
                    // FUNKY TABLE!!!!
                    // 18-Mar-2016 - Standardised to use B1 and 2 ...
                    html.Append("<table class='B0 MaxW' cellpadding='5' cellspacing='0'>");
                    html.Append("<tr class='SummaryTableHeader HeaderGridView'>");
                    html.Append("<td>Computer</td><td>IP Address</td><td>Browser</td><td>Timezone</td><td>Location</td><td style=\"width:50px;max-width:50px;\">Total logins</td><td>Failed logins<br/>(with %)</td><td>Last access date</td>");
                    html.Append("</tr>");

                    int counter = -1;
                    int simpleComputerID = 0;
                    string prevCompID = "";
                    foreach (string[] row in data) {
                        counter++;

                        if (counter % 2 == 0) {
                            html.Append("<tr class='B1'>");
                        } else {
                            html.Append("<tr class='B2'>");
                        }

                        // ComputerID - simply increment a number when we find a new computer
                        if (prevCompID.Equals(row[0]) == false) {
                            simpleComputerID++;
                        }
                        prevCompID = row[0];
                        html.Append("<td class='CE'>" + simpleComputerID + "</td>");

                        // IP Address
                        html.Append("<td class='RI'>" + row[1] + "</td>");
                        // Browser
                        html.Append("<td>" + row[2] + "</td>");
                        // Timezone
                        int tz = 0;
                        int.TryParse(row[3], out tz);
                        html.Append("<td>" + DateTimeInformation.TimezoneText(tz) + "</td>");

                        // Location
                        if (string.IsNullOrEmpty(row[4]) == false) {
                            html.Append("<td>" + row[4] + ", "+row[5]+", "+row[6]+"</td>");
                        } else {
                            html.Append("<td>-</td>");
                        }

                        // Total accesses (e.g. Password resets etc)
                        int tl1 = 0;
                        int.TryParse(row[7], out tl1);
                        html.Append("<td class='RI'>" + tl1.ToString("N0") + "</td>");

                        // Total failed accesses - colour code the results based on the % failed
                        int tl2 = 0;
                        int.TryParse(row[8], out tl2);
                        int perc = (tl2 != 0 && tl1 != 0) ? (int) Math.Round((double)tl2 / (double)tl1 * 100, 0) : 0;
                        string cssClass = "";
                        if (perc > 10 && perc < 50) {
                            cssClass = "class='InfoClassWarning MaxW'";
                        } else if (perc >= 50) {
                            cssClass = "class='InfoClassFailure MaxW'";
                        }
                        html.Append("<td class='RI'><div " + cssClass + ">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tl2.ToString("N0") + " (" + perc + "%)</div></td>");

                        // Last login Date
                        DateTime dt = DateTimeInformation.NullDate;
                        DateTime.TryParse( row[9], out dt);
                        html.Append("<td class='RI'>" + LocaliseTime.Localise(tz, dt) + "</td>");

                        html.Append("</tr>");
                    }
                    html.Append("</table>");
                }

                // got to here then looking good!
                success = true;

            } catch (Exception ex) {
                Logger.LogError(7, "User Location - Problem with BuildLocationSummary for user ID:" + userID
                    + ".  Check it out:" + ex.ToString());

            } finally {
                if (dbInfo != null) {
                    dbInfo.Disconnect();
                }
            }

            return success;
        }



    }
}
