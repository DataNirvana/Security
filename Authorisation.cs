using System;
using System.Web;
using MGL.Data.DataUtilities;
using System.Collections.Generic;
using MGL.DomainModel;
using System.Net;
using System.Xml;
using System.Text;
using System.Security;


//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for Authorise
    /// </summary>
    public class Authorisation {

        //        private ConfigurationInfo lcf = null;
        //        private DatabaseInformation dbInfo = null;

        public static string Functionality = "Functionality";
        public static string Data = "Data";
        public static string Display = "Display";

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static void SetupSecurity(string appName, string appURL, ConfigurationInfo lcf) {
            UserOperations userOps = null;
            GroupOperations groupOps = null;
            try {
                InitSecurityConfig(lcf);
                applicationName = appName;
                applicationURL = appURL;

                userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

                // Extract the Application Level list of Users ...

                //            List<User> allUsers = userOps.GetAllUsers();

                Dictionary<int, MGUser> userDict = userOps.UserDictionary();
                Dictionary<int, List<int>> userGroupDict = userOps.UserGroupDictionary();

                // Extract the Application Level list of groups, along with the relevant cross references to Users and the content etc ...
                groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                List<MGGroup> allGroups = groupOps.GetAllGroups();
                Dictionary<int, List<MGSecurityTag>> groupContentDict = groupOps.GroupContentDictionary();
                Dictionary<int, List<MGSecurityTag>> groupDisplayDict = groupOps.GroupDisplayDictionary();
                Dictionary<int, List<MGSecurityTag>> groupFunctionalityDict = groupOps.GroupFunctionalityDictionary();

                MGLApplicationSecurityInterface.Instance().Groups = allGroups;

                MGLApplicationSecurityInterface.Instance().Users = userDict;
                MGLApplicationSecurityInterface.Instance().UserGroupXref = userGroupDict;
                MGLApplicationSecurityInterface.Instance().GroupContentXref = groupContentDict;
                MGLApplicationSecurityInterface.Instance().GroupDisplayXref = groupDisplayDict;
                MGLApplicationSecurityInterface.Instance().GroupFunctionalityXref = groupFunctionalityDict;
            } catch (Exception ex) {
                Logger.LogError(9, "Problem setting up security at " + ex);
            } finally {
                if (userOps != null)
                    userOps.Finish();

                if (groupOps != null)
                    groupOps.Finish();
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static void InitSecurityConfig(ConfigurationInfo lcf) {
            try {
                MGLApplicationSecurityInterface.Instance().AppLoginConfig = LoginConfig.Instance;
            } catch (Exception e) {
                throw new Exception("Expected login config section in web.config!", e);
            }

            MGLApplicationSecurityInterface.Instance().DatabaseConfig = lcf;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static string applicationName = null;
        public static string ApplicationName {
            get { return applicationName; }
            set { applicationName = value; }
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static string applicationURL = null;
        public static string ApplicationURL {
            get { return applicationURL; }
            set { applicationURL = value; }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Gets the current User Name ...
        /// </summary>
        public static SecureString CurrentUserName {
            get {
                SecureString currentUserName = null;
                MGUser cu = MGLSessionSecurityInterface.Instance().CurrentUser;
                if (cu != null) {
                    currentUserName = cu.Username;
                }
                return currentUserName;
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     14-Aug-2015 - Hashing the email and appending this to URLs is weak security policy - better to use a completely random info
        ///     like the MGL session ID
        /// </summary>
        /// <returns></returns>
        public static string CurrentUserHash(string token) {

            string hash = MD5Hash.GetMd5Sum(token);
            return hash;

        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static MGUser CurrentUser {
            get {
                return MGLSessionSecurityInterface.Instance().CurrentUser;
            }
        }



        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Try to get the User Information for the Given ID - Note not very secure and could be abused ....
        /// </summary>
        public static bool GetUser(int userID, out MGUser applicationUser) {

            applicationUser = new MGUser();

            bool success = MGLApplicationSecurityInterface.Instance().Users.TryGetValue(userID, out applicationUser);
            return success;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     4th Feb 2014 - Try to get the User Information for the Given UserName - Note not very secure and could be abused ....
        ///     2-Dec-2015 - extended so this tests the given userName against BOTH the userName AND the email address from the global list of users
        ///     as this is how this method is now being used.
        /// </summary>
        public static bool GetUser(SecureString userNameOrEmail, out MGUser applicationUser) {

            bool success = false;

            applicationUser = new MGUser();

            if (userNameOrEmail != null && userNameOrEmail.Length > 0 && MGLApplicationSecurityInterface.Instance().Users != null) {

                foreach (MGUser u in MGLApplicationSecurityInterface.Instance().Users.Values) {
                    if (SecureStringWrapper.AreEqual(u.Username, userNameOrEmail, false) || SecureStringWrapper.AreEqual(u.Email, userNameOrEmail, false)) {
                        applicationUser = u;
                        success = true;
                        break;
                    }
                }

            }

            return success;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static Dictionary<string, string> functionalityDescriptions = null;
        public static Dictionary<string, string> FunctionalityDescriptions {
            get {
                if (functionalityDescriptions == null) {
                    GroupOperations groupOps = null;
                    try {
                        groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                        functionalityDescriptions = groupOps.GetFunctionalityDescriptionDictionary();
                        if (functionalityDescriptions == null) {
                            Logger.LogError(5, "Failed to get FunctionalityDescriptions!");
                        }
                    } catch (Exception ex) {
                        Logger.LogError(5, "Failed to get FunctionalityDescriptions at " + ex);
                        return null;
                    } finally {
                        if (groupOps != null) {
                            groupOps.Finish();
                        }
                    }
                }

                return functionalityDescriptions;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Checks in the security_groups to user xref to see
        /// if the CURRENT USER belongs to a group with the
        /// same group name (group type)
        /// </summary>
        /// <param name="groupType"></param>
        /// <returns></returns>
        public static bool BelongsToGroup(MGGroupType groupType) {
            bool result = false;

            GroupOperations groupOps = null;

            try {
                groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                MGUser currentUser = MGLSessionSecurityInterface.Instance().CurrentUser;
                MGGroup group = groupOps.GetGroup(groupType.ToString());

                if (group != null) {
                    if (MGLApplicationSecurityInterface.Instance().UserGroupXref.ContainsKey(currentUser.ID)) {
                        List<int> thisUsersGroups = MGLApplicationSecurityInterface.Instance().UserGroupXref[currentUser.ID];

                        //See if this user is in this group
                        if (thisUsersGroups.Contains(group.ID)) {
                            result = true;
                        }
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error testing if current user belongs to a group." + ex.Message);
                return false;
            } finally {
                if (groupOps != null)
                    groupOps.Finish();
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool BelongsToGroupWS(MGUser currentUser, MGGroupType groupType) {
        //    bool result = false;

        //    GroupOperations groupOps = null;

        //    try {
        //        groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

        //        MGGroup group = groupOps.GetGroup(groupType.ToString());

        //        if (group != null) {
        //            if (MGLApplicationSecurityInterface.Instance().UserGroupXref.ContainsKey(currentUser.ID)) {
        //                List<int> thisUsersGroups = MGLApplicationSecurityInterface.Instance().UserGroupXref[currentUser.ID];

        //                //See if this user is in this group
        //                if (thisUsersGroups.Contains(group.ID)) {
        //                    result = true;
        //                }
        //            }
        //        }
        //    } catch (Exception ex) {
        //        Logger.LogError("Error testing if current user belongs to a group." + ex.Message);
        //        return false;
        //    } finally {
        //        if (groupOps != null)
        //            groupOps.Finish();
        //    }

        //    return result;
        //}




        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static List<int> GetUsersGroupIDs(int userID) {
            List<int> result = null;

            try {
                if (MGLApplicationSecurityInterface.Instance().UserGroupXref.ContainsKey(userID)) {
                    result = MGLApplicationSecurityInterface.Instance().UserGroupXref[userID];
                }
            } catch {
            }

            return result;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Checks in the security_groups to user xref to see
        /// if the CURRENT USER belongs to a group with the
        /// same group name (group type)
        /// </summary>
        /// <param name="groupType"></param>
        /// <returns></returns>
        public static List<MGGroup> AllAvailableGroups() {
            List<MGGroup> result = null;

            GroupOperations groupOps = null;

            try {
                groupOps = new GroupOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                result = groupOps.GetAllGroups();
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting AllAvailableGroups." + ex.Message);
            } finally {
                if (groupOps != null)
                    groupOps.Finish();
            }

            return result;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Checks whether or not the currently logged in user is authorised to view or edit the information recorded in the type and specific element
        ///     e.g. user groups of administrators ...
        /// </summary>
        public static bool DoIsAuthorised(string tagClass, string tagName) {
            return DoIsAuthorised(tagClass, tagName, 0);
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool DoIsAuthorised(string tagClass, string tagName, int tagSubType) {
            if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseExternalLoginSite) {
                //return IsAuthorisedWS(tagClass, tagName);
                // Kill this for now (12-Oct-2015)
                throw new Exception();
            } else {
                return IsAuthorised(tagClass, tagName, 0);
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///  Todo!!!
        /// </summary>
        //public static bool IsAuthorisedWS(string tagClass, string tagName) {
        //    return true;
        //}


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool IsAuthorised(string tagClass, string tagName) {
            return IsAuthorised(tagClass, tagName, 0);
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool IsAuthorised(string tagClass, string tagName, int tagSubType) {

            bool isAuth = false;
            //lcf = LCF;
            //dbInfo = new DatabaseInformation(false, lcf);
            //dbInfo.Connect();
            if (SecuritySetup.RequireSecurity == false) {
                isAuth = true;
            } else {
                if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.BypassLogin) {
                    isAuth = true;
                } else if (tagName == null || tagName == "" || tagClass == null || tagClass == "") {    // disAllow by default
                    isAuth = false;
                } else {

                    // if user is not set, we cannot authorise ...
                    MGUser currentUser = MGLSessionSecurityInterface.Instance().CurrentUser;
                    if (currentUser != null) {
                        // Do the authorisation ...
                        // Step 1 - get the groups that the user relates to
                        List<int> groupIDs = null;
                        MGLApplicationSecurityInterface.Instance().UserGroupXref.TryGetValue(currentUser.ID, out groupIDs);

                        if (groupIDs != null) {

                            // Step 2 - Build the security tag and see if that exists when related to any of the groups that relate to this user
                            MGSecurityTag secTag = new MGSecurityTag(tagName.ToLower(), tagSubType);

                            Dictionary<int, List<MGSecurityTag>> securityDict = null;

                            if (tagClass.ToLower().Equals(SecurityFeatureClasses.Content)) {
                                securityDict = MGLApplicationSecurityInterface.Instance().GroupContentXref;
                            } else if (tagClass.ToLower().Equals(SecurityFeatureClasses.Functionality)) {
                                securityDict = MGLApplicationSecurityInterface.Instance().GroupFunctionalityXref;
                            } else if (tagClass.ToLower().Equals(SecurityFeatureClasses.Display)) {
                                securityDict = MGLApplicationSecurityInterface.Instance().GroupDisplayXref;
                            } else if (tagClass.ToLower().Equals(SecurityFeatureClasses.Group)) {

                                // 9th July 2014 - Extend this so we can check on a specific group type in the code ...
                                foreach (MGGroup group in MGLApplicationSecurityInterface.Instance().Groups) {
                                    if (tagName != null && tagName.Equals(group.Name, StringComparison.CurrentCultureIgnoreCase)) {
                                        foreach (int gID in groupIDs) {
                                            //                                            isAuth = true;
                                            if (gID == group.ID) { // This User is linked to the group that is requested in the IsAuthorised method ...
                                                return true;
                                            }
                                        }
                                    }
                                }


                            } else {

                                //                                string fuckedItUp = "";
                            }

                            if (securityDict != null) {
                                foreach (int groupID in groupIDs) {
                                    List<MGSecurityTag> secTags = null;
                                    if (securityDict.TryGetValue(groupID, out secTags)) {
                                        // if our secTag is contained in these seg tags, every one is a winner

                                        if (IsSecTagContained(secTags, secTag)) {
                                            return true;
                                        }
                                        //if (secTags.Contains(secTag)) {
                                        //    return true;
                                        //}
                                    }

                                }
                            }
                        }
                    }
                }
            }
            return isAuth;
        }

        public static bool IsSecTagContained(List<MGSecurityTag> secTags, MGSecurityTag searchSecTag) {
            bool isContained = false;

            if (secTags == null || secTags.Count == 0)
                return false;

            foreach (MGSecurityTag secTag in secTags) {
                if (
                    secTag.Name.Equals(searchSecTag.Name, StringComparison.CurrentCultureIgnoreCase) &&
                    secTag.SubType == searchSecTag.SubType
                   ) {
                    return true;
                }
            }

            return isContained;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool DoIsLoggedIn() {
            if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseExternalLoginSite) {
                //return CheckIsLoggedInWS();
                // 12-Oct-2015 - lets kill the WS code for now ..
                throw new Exception();
            } else {
                return CheckIsLoggedInLocal();
            }
        }

        /// <summary>
        /// For the user matching userid get the last time they updated their password
        /// if the user is not found method will return null
        /// if the password change date isnt set the method will return start date (if valid)
        /// </summary>
        /// <param name="userID"></param>
        /// <returns></returns>
        public static DateTime GetPasswordChangeDate(int userID) {

            DateTime result = DateTime.MinValue;

            UserOperations userOps = null;
            try {
                userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
                result = userOps.GetPasswordChangeDate(userID);
            } catch (Exception ex) {
                Logger.LogError(5, "Error in Authorisation.GetPasswordChangeDate() " + ex.Message);
            } finally {
                if (userOps != null)
                    userOps.Finish();
            }

            return result;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool CheckIsLoggedInWS() {
        //    bool isLoggedIn = false;

        //    string currentIP = "";
        //    string hashedEmail = "";
        //    try {
        //        // get the current user and pass on the email as a hash and the current ip
        //        currentIP = System.Web.HttpContext.Current.Request.UserHostAddress;

        //        if (MGLSessionSecurityInterface.Instance().CurrentUser != null) {
        //            string tempEmail = SecureStringWrapper.Decrypt( MGLSessionSecurityInterface.Instance().CurrentUser.Email ).ToString();
        //            hashedEmail = MD5Hash.GetMd5Sum(tempEmail);
        //        }

        //        //@@Logger.LogError("Authorisation.CheckIsLoggedInWS - CurrentIP ..." + currentIP + " hashed Email: " + hashedEmail);

        //        // check with the website ...
        //        //                ServicePointManager.CertificatePolicy = new MGL.GEDI.Security.MGHTTPsValidation();

        //        string protocol = MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS ? "https://" : "http://";
        //        string url = protocol + MGLApplicationSecurityInterface.Instance().AppLoginConfig.ExternalLoginURL
        //            + "/IsLoggedIn?key=" + hashedEmail + "&ip=" + currentIP;

        //        XmlDocument xmlDoc = new XmlDocument();
        //        xmlDoc.Load(url);

        //        XmlNodeList trueOrFalse = xmlDoc.GetElementsByTagName("boolean");
        //        foreach (XmlNode node in trueOrFalse) {
        //            if (node.ChildNodes != null) {
        //                bool tempBool = false;
        //                bool.TryParse(node.ChildNodes[0].Value, out tempBool);
        //                isLoggedIn = tempBool;
        //            }
        //        }

        //        //                string temp = "";

        //    } catch (Exception ex) {
        //        Logger.LogError("Authorisation.CheckIsLoggedInWS - CurrentIP ..." + currentIP + " hashed Email: " + hashedEmail + "  ex = " + ex.ToString());
        //    }

        //    return isLoggedIn;
        //}

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool CheckIsLoggedInLocal() {

            bool loggedIn = false;

            if (SecuritySetup.RequireSecurity == false) {
                loggedIn = true;
            } else {
                MGUser currentUser = MGLSessionSecurityInterface.Instance().CurrentUser;

                // Step 1 - check to see if ByPassLogin is authorised
                if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.BypassLogin == true) {

                    loggedIn = true;

                    //// if it is, log the user in as a guest, if not already logged in
                    //if (IsLoggedIn() == false) {
                    //    Login(GuestUserName, GuestPassword);
                    //}

                    // Step 2 - Otherwise check to see if the user is logged in
                } else if (currentUser != null) {
                    // also compare the UserName to the application level list of users
                    MGUser appUser = null;
                    if (MGLApplicationSecurityInterface.Instance().Users.TryGetValue(currentUser.ID, out appUser)) {
                        if (SecureStringWrapper.AreEqual( appUser.Username, currentUser.Username, true)) {

                            // 2-Oct-2015 - We also need to catch the case where someone opens a laptop at a different location
                            // and therefore the IP address changes
                            // MORE IMPORTANTLY - this makes it hard for people to steal session identity just using the ASP.net cookie
                            // they would now also need to spoof the IP address as well, which is a (slightly) more sophisticated attack
                            // 27-Nov-2015 - Converted to use this v4IPAddress method.
                            //string currentIPAddress = HttpContext.Current.Request.UserHostAddress;
                            string currentIPAddress = IPAddressHelper.GetIP4OrAnyAddressFromHTTPRequest();

                            if (currentIPAddress != null && currentIPAddress.Equals(currentUser.LastIP, StringComparison.CurrentCultureIgnoreCase)) {

                                loggedIn = true;

                            } else {
                                Logger.LogError( 113, "WARNING - user "+currentUser.ID+" has just request a page using a different IP address.  "
                                    +"Probably because they are viewing the system on a laptop and closed and reopened it in a new location.  Keep an eye on it!" );
                                Logout();
                            }
                        }
                    }

                    // Step 3 - Otherwise, if automated login, get the user name from the context ...
                } else if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.EnableAutomatedLogin) {

                    string userName = HttpContext.Current.User.Identity.Name;
                    userName = userName.Substring(userName.IndexOf("\\") + 1);

                    // attempt to login
                    loggedIn = DoLogin(SecureStringWrapper.Encrypt( userName ), null);

                }
            }

            return loggedIn;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///  Called from an authorisation web service
        /// </summary>
        //public static bool IsLoggedInWS(string emailHash, string ipAddress) {
        //    bool isLoggedIn = false;

        //    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == false
        //        || (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == true && WebProtocol.Equals("https", StringComparison.CurrentCultureIgnoreCase))) {

        //        ConfigurationInfo lcf = MGLApplicationSecurityInterface.Instance().DatabaseConfig;
        //        AuthorisationOperations authOps = new AuthorisationOperations(lcf);
        //        isLoggedIn = authOps.IsLoggedInWS(emailHash, ipAddress);

        //    } else {
        //        Logger.LogError("Could not log user in as HTTPS protocol required, but not provided.  Sort it out");
        //    }
        //    return isLoggedIn;
        //}


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>If the currently logged in user belongs to a group with User edit rights, they can do this here</summary>
        public static bool ResetIncorrectLogins(string userName) {
            //lcf = LCF;
            //dbInfo = new DatabaseInformation(false, lcf);
            //dbInfo.Connect();



            return false;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static void Logout() {
            MGLSessionSecurityInterface.Instance().ClearAll();
            SecureContentWrapper.LiveDbContextInstance = null;
            //  SecureContentWrapper.StagingDbContextInstance = null;
        }


        ////---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool DoLogin(SecureString userName, SecureString password) {
        //    bool isLoggedIn = false;

        //    //@@Logger.LogError("Authorisation.DoLogin - Attempting ...");

        //    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseExternalLoginSite) {
        //        MGUser tempUser = new MGUser();

        //        string protocol = MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS ? "https://" : "http://";
        //        string url = protocol + MGLApplicationSecurityInterface.Instance().AppLoginConfig.ExternalLoginURL + "/Login?UserName="
        //            + SecureStringWrapper.Decrypt( userName ) + "&Password="
        //            + SecureStringWrapper.Decrypt( password );

        //        XmlDocument xmlDoc = new XmlDocument();
        //        MGUser u = new MGUser();

        //        try {
        //            xmlDoc.Load(url);
        //            u = UserParseXML.ParseUser(xmlDoc);
        //            if (u.ID != int.MaxValue) {

        //                UserOperations userOps = null;

        //                try {
        //                    userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
        //                    userOps.LogLogin(u.ID, true);
        //                    // This means that the webservice and this web application need to view the same database ....
        //                    u = userOps.GetUser(u.ID);
        //                } catch (Exception ex) {
        //                    Logger.LogError("Problem loggin in at " + ex);
        //                } finally {
        //                    if (userOps != null)
        //                        userOps.Finish();
        //                }

        //                MGLSessionSecurityInterface.Instance().CurrentUser = u;
        //                isLoggedIn = true;

        //                //@@Logger.LogError("Authorisation.DoLogin - Assigned to the security interface do da ...");
        //            }


        //        } catch (Exception ex) {
        //            Logger.LogError("Authorisation.DoLogin - Problem! ...  Using HTTPS:" + MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS + "   " + ex.ToString());
        //        }

        //        //@@string temp = "";

        //    } else {
        //        isLoggedIn = Login(userName, password);
        //    }

        //    //@@Logger.LogError("Authorisation.DoLogin - Success?? ..." + isLoggedIn);

        //    return isLoggedIn;
        //}



        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool DoLogin(SecureString userName, SecureString password) {
            AuthorisationOperations authOps = new AuthorisationOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
            bool loggedIn = authOps.Login(userName, password);

            return loggedIn;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static MGUser LoginWS(SecureString userName, SecureString password) {
        //    MGUser loggedInUser = new MGUser();

        //    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == false
        //        || (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == true && WebProtocol.Equals("https", StringComparison.CurrentCultureIgnoreCase))) {

        //        ConfigurationInfo lcf = MGLApplicationSecurityInterface.Instance().DatabaseConfig;
        //        AuthorisationOperations authOps = new AuthorisationOperations(lcf);
        //        loggedInUser = authOps.LoginWS(userName, password);

        //    } else {
        //        Logger.LogError("Could not log user in as HTTPS protocol required, but not provided.  Sort it out");
        //    }
        //    return loggedInUser;
        //}

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool ApplyUserCredentials(string hashedEmail) {
        //    bool isLoggedIn = false;

        //    //@@Logger.LogError("Authorisation.ApplyUserCredentials - Hash ..." + hashedEmail);

        //    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseExternalLoginSite) {
        //        MGUser tempUser = new MGUser();

        //        string currentIP = System.Web.HttpContext.Current.Request.UserHostAddress;

        //        string protocol = MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS ? "https://" : "http://";
        //        string url = protocol + MGLApplicationSecurityInterface.Instance().AppLoginConfig.ExternalLoginURL
        //            + "/GetUserCredentials?key=" + hashedEmail + "&ip=" + currentIP;

        //        XmlDocument xmlDoc = new XmlDocument();
        //        MGUser u = new MGUser();


        //        try {
        //            xmlDoc.Load(url);
        //            u = UserParseXML.ParseUser(xmlDoc);
        //            if (u.ID != int.MaxValue) {
        //                MGLSessionSecurityInterface.Instance().CurrentUser = u;
        //                isLoggedIn = true;
        //            }

        //            //@@Logger.LogError("Authorisation.ApplyUserCredentials - User ..." + u.Username);

        //        } catch (Exception ex) {
        //            Logger.LogError("Authorisation.ApplyUserCredentials - Hash ..." + hashedEmail + " ex = " + ex.ToString());
        //        }

        //    }
        //    //@@Logger.LogError("Authorisation.ApplyUserCredentials - Success?? ..." + isLoggedIn);

        //    return isLoggedIn;
        //}


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///  Called from an authorisation web service
        /// </summary>
        //public static MGUser GetUserCredentialsWS(SecureString emailHash, string ipAddress) {
        //    MGUser loggedInUser = new MGUser();

        //    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == false
        //        || (MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == true && WebProtocol.Equals("https", StringComparison.CurrentCultureIgnoreCase))) {

        //        ConfigurationInfo lcf = MGLApplicationSecurityInterface.Instance().DatabaseConfig;
        //        AuthorisationOperations authOps = new AuthorisationOperations(lcf);
        //        loggedInUser = authOps.GetUserCredentials(emailHash, ipAddress);

        //    } else {
        //        Logger.LogError("Could not log user in as HTTPS protocol required, but not provided.  Sort it out");
        //    }
        //    return loggedInUser;
        //}


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string LoginError() {

            AuthorisationOperations authOps = new AuthorisationOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
            return authOps.LoginError();
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     The error that is triggered by spambots
        /// </summary>
        /// <returns></returns>
        public static string GeneralError {
            get { return "Please try again in a moment and contact us if this reoccurs."; }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool AllowGuests {
            get {
                return MGLApplicationSecurityInterface.Instance().AppLoginConfig.AllowGuests;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool AllowRegistration {
            get {
                return MGLApplicationSecurityInterface.Instance().AppLoginConfig.AllowRegistration;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool ShowTermsAndConditions {
            get {
                return MGLApplicationSecurityInterface.Instance().AppLoginConfig.ShowTermsAndConditions;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool FrontPageIsSecure {
        //    get {
        //        return MGLApplicationSecurityInterface.Instance().AppLoginConfig.SecureFrontPage;
        //    }
        //}





        /// <summary>
        /// If this is true the system will use mgl encryption on user passwords
        /// This means we will be able to decrypt passwords for the
        /// Password reminder functionality
        /// </summary>
        public static bool UseMGLRatherThanMySQLPasswordEncryption {
            get {
                return MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseMGLRatherThanMySQLPasswordEncryption;
            }
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool AutomatedLoginIsEnabled {
            get {
                if (SecuritySetup.RequireSecurity == false) {
                    return true;
                } else {
                    return MGLApplicationSecurityInterface.Instance().AppLoginConfig.EnableAutomatedLogin;
                }
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool BypassLogin {
            get {
                return MGLApplicationSecurityInterface.Instance().AppLoginConfig.BypassLogin;
            }
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static readonly SecureString GuestUserName = SecureStringWrapper.Encrypt( "Guest" );
        public static readonly SecureString GuestPassword = SecureStringWrapper.Encrypt( "" );
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string LoginPage {
            get { return MGLApplicationSecurityInterface.LoginPage; }
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string NoEntryPage {
            get { return MGLApplicationSecurityInterface.NoEntryPage; }
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string DefaultPage {
            get { return MGLApplicationSecurityInterface.Instance().AppLoginConfig.DefaultPostLoginPage; }
        }

        public static string RegistrationPageURL {
            get { return MGLApplicationSecurityInterface.Instance().AppLoginConfig.RegistrationPageURL; }
        }

        //------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string WebProtocol {
            get {

                string protocol = HttpContext.Current.Request.ServerVariables["SERVER_PORT_SECURE"];

                if (protocol == null || protocol == "0")
                    return "http";
                else
                    return "https";

            }
        }

        ////--------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public static bool TestPasswordEncryption() {
        //    bool success = false;

        //    string clearText = "n4rrat0r";
        //    Logger.Log("Password is: '" + clearText + "'");

        //    string password = MGLPasswordHash.EncryptPassword(new StringBuilder(clearText));

        //    Logger.Log("Encrypted Password is: '" + password + "'");

        //    return success;
        //}

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string CreateUpdateLoginSuccessSql(MGUser mgUser) {
            StringBuilder builder = new StringBuilder();

            builder.Append("UPDATE " + BaseSecurityOperations.tnUsers + @" SET NumberOfIncorrectLogins=0");

            builder.Append(", LastLoginDate='");
            builder.Append(DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString());
            builder.Append("'");
            builder.Append(",TotalLogins=");

            builder.Append((mgUser.TotalLogins + 1).ToString());

            // Last IP
            builder.Append(",LastIP=");
            builder.Append("'");
            // 27-Nov-2015 - Converted to use this v4IPAddress method.
//            builder.Append(HttpContext.Current.Request.UserHostAddress);
            builder.Append(IPAddressHelper.GetIP4OrAnyAddressFromHTTPRequest());
            builder.Append("'");

            // Last browser
            builder.Append(", LastBrowser=");
            builder.Append("'");
            builder.Append(HttpContext.Current.Request.Browser.Browser);
            builder.Append(" ");
            builder.Append(HttpContext.Current.Request.Browser.Version);
            builder.Append("'");
            builder.Append(" WHERE ID=");
            builder.Append(mgUser.ID);
            builder.Append(";");

            return builder.ToString();
        }

        public static string CreateUpdateLoginFailSql(MGUser mgUser) {
            StringBuilder builder = new StringBuilder();

            builder.Append("UPDATE " + BaseSecurityOperations.tnUsers + @" SET NumberOfIncorrectLogins = ");
            builder.Append((mgUser.NumIncorrectLogins + 1).ToString());
            builder.Append(" WHERE ID=");
            builder.Append(mgUser.ID);
            builder.Append(";");

            return builder.ToString();
        }

        public static string CreateGetUserByName(string username) {
            string checkedUserName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, username);

            StringBuilder builder = new StringBuilder();

            builder.Append(@"
                SELECT ID,
                Username,
                Password,
                Email,
                Organisation,
                JobTitle,
                Telephone,
                TotalLogins,
                LastLoginDate,
                LastIP,
                LastBrowser,
                NumberOfIncorrectLogins
                FROM " + BaseSecurityOperations.tnUsers + @"
                WHERE UserName = '");

            builder.Append(checkedUserName.ToString());

            builder.Append("'");

            return builder.ToString();
        }


        public static string CreateGetUserByNameAndEmail(string username, string email) {
            string checkedUserName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, username);
            string checkedEmail = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, email);

            StringBuilder builder = new StringBuilder();

            builder.Append(@"
                SELECT ID,
                Username,
                Password,
                Email,
                Organisation,
                JobTitle,
                Telephone,
                TotalLogins,
                LastLoginDate,
                LastIP,
                LastBrowser,
                NumberOfIncorrectLogins
                FROM " + BaseSecurityOperations.tnUsers + @"
                WHERE UserName = '");

            builder.Append(checkedUserName.ToString());

            builder.Append("'");

            builder.Append(" AND Email = '");

            builder.Append(checkedEmail.ToString());

            builder.Append("'");

            return builder.ToString();
        }

        public static string CreateGetUserByEmail(string email) {
            StringBuilder builder = new StringBuilder();

            string checkedEmail = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, email);

            builder.Append(@"
                SELECT ID,
                UserName as username,
                Password,
                Email,
                Organisation,
                JobTitle,
                Telephone,
                TotalLogins,
                LastLoginDate,
                LastIP,
                LastBrowser,
                NumberOfIncorrectLogins
                FROM " + BaseSecurityOperations.tnUsers + @"
                WHERE Email = '");

            builder.Append(checkedEmail.ToString());

            builder.Append("'");

            return builder.ToString();
        }

        public static string CreateAddUserSql(string username, string password, string email, string organisation, string jobTitle, string telephone) {
            StringBuilder builder = new StringBuilder();

            string checkedUserName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, username);
            string checkedUserPassword = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, password);
            string checkedUserEmail = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, email);
            string checkedUserOrganisation = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, organisation);
            string checkedUserJobTitle = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, jobTitle);
            string checkedUserTelephone = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, telephone);

            builder.Append(" INSERT INTO administrator ");
            builder.Append("(UserName, UserType, Password, Email, Organisation, JobTitle, Telephone, TotalLogins, LastLogin, NumberOfIncorrectLogins, IsNew, LastIP, LastBrowser) ");
            builder.Append(" VALUES ");
            builder.Append(" ( ");

            builder.Append("'");
            builder.Append(checkedUserName);
            builder.Append("', ");

            builder.Append("'");
            builder.Append(checkedUserPassword);
            builder.Append("', ");

            builder.Append(checkedUserEmail == null ? "NULL" : "'" + checkedUserEmail + "'");
            builder.Append(", ");

            builder.Append(checkedUserOrganisation == null ? "NULL" : "'" + checkedUserOrganisation + "'");
            builder.Append(", ");

            builder.Append(checkedUserJobTitle == null ? "NULL" : "'" + checkedUserJobTitle + "'");
            builder.Append(", ");

            builder.Append(checkedUserTelephone == null ? "NULL" : "'" + checkedUserTelephone + "'");
            builder.Append(", ");

            // Total logins
            builder.Append("1,");

            // Last login date and time
            builder.Append("'");
            builder.Append(DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString());
            builder.Append("', ");

            // Incorrect logins
            builder.Append("0, ");

            // Is new
            builder.Append("1, ");

            // Last IP
            builder.Append("'");
            // 27-Nov-2015 - Converted to use this v4IPAddress method.
            //builder.Append(HttpContext.Current.Request.UserHostAddress);
            builder.Append(IPAddressHelper.GetIP4OrAnyAddressFromHTTPRequest());
            builder.Append("', ");

            // Last browser
            builder.Append("'");
            builder.Append(HttpContext.Current.Request.Browser.Browser);
            builder.Append(" ");
            builder.Append(HttpContext.Current.Request.Browser.Version);
            builder.Append("'");

            builder.Append(" ); ");

            return builder.ToString();
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Checks to see if a user has requested a password reset widget
        /// </summary>
        public static bool UserHasRequestedResetPassword(int userID) {

            PasswordResetWidget prw = PasswordReset.GetWidget(userID);

            bool hasRequested = (prw.Token != null && prw.Token.Length > 0);

            return hasRequested;
        }

        // might need to add another method here to get the redirect URL for resetting the password ...

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Checks to see if a user has requested a password reset widget
        /// </summary>
        public static bool CheckPasswordResetPasswordTokenIsValid(StringBuilder encryptedToken, out int userID, out string errorMessage) {

            bool success = false;
            errorMessage = "";
            userID = 0;

            if (encryptedToken == null || encryptedToken.Length == 0) {
                // 30-Oct-2015 - Catch no token to check the validity of ... probably as the user has modified the URL themselves?.
                errorMessage = "The reset link is corrupted.  Please request another one by clicking on the forgot password link on the login page.";
                Logger.LogError(7, "PasswordReset CheckPasswordResetPasswordTokenIsValid - No reset link was provided - probably as the user has modified the URL themselves");

            } else {
                // get the decrypted token ...
                StringBuilder rToken = MGLEncryption.DeHTMLifyString(encryptedToken);
                StringBuilder decryptedToken = MGLEncryption.Decrypt(rToken);

                // get the widget for this user ....
                PasswordResetWidget prw = PasswordReset.GetWidget(decryptedToken);

                // compare the token and check that it is still valid ...
                if (prw == null || prw.Token == null || MGLEncryption.AreEqual( prw.Token, decryptedToken) == false) {

                    errorMessage = "This reset link is no longer valid";

                } else {

                    TimeSpan t = DateTime.Now.Subtract(prw.TimeStamp);
                    if (t.TotalMinutes > 60) {

                        errorMessage = "This reset link has expired and is no longer valid";

                    } else {
                        userID = prw.UserID;
                        success = true;
                    }
                }
            }

            return success;
        }

    }

}