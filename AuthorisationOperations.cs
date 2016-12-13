using System;
using System.Data;
using System.Configuration;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using System.Security;

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for AuthorisationOperations
    /// </summary>
    internal class AuthorisationOperations {

        private ConfigurationInfo lcf = null;

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public AuthorisationOperations(ConfigurationInfo configFile) {
            lcf = configFile;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        public bool Login( User user, string password) {
        public bool Login(SecureString userName, SecureString password) {
            bool loggedIn = false;
            string loginError = "Username or password not recognised.";

            UserOperations userOps = null;

            try {


                if (userName != null) {
                    userOps = new UserOperations(lcf);

                    MGUser user = userOps.GetUser(userName);

                    // check the number of logins has not been exceeded
                    if (user != null) {

                        if (user.IsLockedOut == true) {
                            loginError = "Too many incorrect attempts.  Please contact the web team."; // to unlock your account.";
                        } else {

                            // 30-Nov-2015 - Strip the password out of the user information as this is applied to the session
                            user.Password = null;

                            // Check the password
                            if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.EnableAutomatedLogin == false && password != null) {
                                // check the user name and the encrypted password in the database

                                bool userLoginDetailsCorrect = userOps.UserLoginDetailsCorrect(user.Username, password);
                                // if incorrect, increment the incorrect logins
                                // if correct, increment the total logins

                                userOps.LogLogin(user.ID, userLoginDetailsCorrect);
                                // reextract the user as the LastIP and login date will have changed - better to keep this consistent, if its used for validation in the future ...
                                user = userOps.GetUser(user.ID);

                                if (userLoginDetailsCorrect) {
                                    loggedIn = true;
                                    // Set the current user object in the session
                                    loginError = null;
                                    MGLSessionSecurityInterface.Instance().CurrentUser = user;
                                }
                            } else {
                                loggedIn = true;
                                // Set the current user object in the session
                                loginError = null;
                                MGLSessionSecurityInterface.Instance().CurrentUser = user;
                            }
                        }

                        if (loggedIn) {
                            SecureContentWrapper.LiveDbContextInstance = new SecureContentWrapper(AppSecurityContext.MainDbLcf);
                            // SecureContentWrapper.StagingDbContextInstance = new SecureContentWrapper(AppSecurityContext.StagingDbLcf);
                        }
                    }
                }

            } catch (Exception ex) {
                Logger.LogError(7, "Problem logging in at " + ex);
            } finally {
                if (userOps != null)
                    userOps.Finish();
            }

            MGLSessionSecurityInterface.Instance().SecurityError = loginError;
            return loggedIn;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///  Called from an authorisation web service
        /// </summary>
        //public MGUser LoginWS(SecureString userName, SecureString password) {

        //    //@@
        //    //Logger.LogError("AuthorisationOperations.LoginWS - attempting ...");

        //    MGUser loggedInUser = new MGUser();
        //    bool loggedIn = false;
        //    string loginError = "Invalid username or password.";

        //    UserOperations userOps = null;

        //    try {
        //        if (userName != null) {
        //            userOps = new UserOperations(lcf);

        //            MGUser user = userOps.GetUser(userName);

        //            // check the number of logins has not been exceeded
        //            if (user != null) {

        //                if (user.IsLockedOut == true) {
        //                    loginError = "The maximum number of incorrect login attempts has been exceeded - Contact the website administrator to unlock your account.";
        //                } else {

        //                    // Check the password
        //                    if (MGLApplicationSecurityInterface.Instance().AppLoginConfig.EnableAutomatedLogin == false && password != null) {
        //                        // check the user name and the encrypted password in the database

        //                        bool userLoginDetailsCorrect = userOps.UserLoginDetailsCorrect(user.Username, password);
        //                        // if incorrect, increment the incorrect logins
        //                        // if correct, increment the total logins

        //                        // The IP address wont be correct here, but the login time will be ...
        //                        userOps.LogLogin(user.ID, userLoginDetailsCorrect);

        //                        if (userLoginDetailsCorrect) {
        //                            loggedIn = true;
        //                            // Set the current user object in the session
        //                            loginError = null;
        //                        }
        //                    } else {
        //                        loggedIn = true;
        //                        // Set the current user object in the session
        //                        loginError = null;
        //                    }
        //                }

        //                if (loggedIn) {
        //                    loggedInUser = user;
        //                    //@@Logger.LogError("AuthorisationOperations.LoginWS - success!!! ...");
        //                } else {
        //                    //@@Logger.LogError("AuthorisationOperations.LoginWS - login unsuccess ful ...");
        //                }
        //            }
        //        }
        //    } catch (Exception ex) {
        //        Logger.LogError(8, "Problem logging in (in WS) at " + ex);
        //    } finally {
        //        if (userOps != null)
        //            userOps.Finish();
        //    }

        //    //MGLSessionSecurityInterface.Instance().SecurityError = loginError;
        //    if (loggedIn == false) {
        //        Logger.LogError(8, "AuthorisationOperations LoginExternal: " + loginError);
        //    }
        //    return loggedInUser;
        //}



        ////---------------------------------------------------------------------------------------------------------------------------------------------------------------
        ///// <summary>
        /////  Called from an authorisation web service
        ///// </summary>
        //public bool IsLoggedInWS(SecureString emailHash, string ipAddress) {

        //    bool loggedIn = false;
        //    //string loginError = "Invalid email or ip address";

        //    if (emailHash != null && ipAddress != null) {

        //        MGUser user = GetUserCredentials(emailHash, ipAddress);

        //        // check the number of logins has not been exceeded
        //        if (user != null && user.ID != int.MaxValue) {

        //            if (user.IsLockedOut == true) {
        //                //loginError = "The maximum number of incorrect login attempts has been exceeded - Contact the website administrator to unlock your account.";
        //            } else {
        //                loggedIn = true;
        //            }
        //        }
        //    }
        //    return loggedIn;
        //}


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///  Called from an authorisation web service
        /// </summary>
        public MGUser GetUserCredentials(SecureString emailHash, string ipAddress) {
            MGUser user = new MGUser();

            try {

                if (emailHash != null && ipAddress != null) {

                    UserOperations userOps = null;

                    try
                    {
                        userOps = new UserOperations(lcf);

                        user = userOps.GetUser(emailHash, ipAddress);

                        //@@Logger.LogError("AuthorisationOperations.GetUserCredentials - User ..." + user.Username);

                        // One final check - check that the time of login is not less than a certain period of time ...
                        // WHy?????
                        //if (user != null && user.LastLogin != null)
                        //{
                        //    if (TimeSpan.Compare(lcf.__WebsiteAbsoluteTimeOut, DateTime.Now.Subtract(user.LastLogin)) < 1)
                        //    {
                        //        user = new MGUser();
                        //    }
                        //}
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(9, "Problem getting user credentials at " + ex);
                    }
                    finally
                    {
                        if (userOps != null)
                            userOps.Finish();
                    }

                    //@@Logger.LogError("AuthorisationOperations.GetUserCredentials - User after time check ..." + user.Username);
                }
            } catch (Exception ex) {
                Logger.LogError(9, "AuthorisationOperations.GetUserCredentials - Error processing ..." + ex.ToString());
            }
            return user;
        }



        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        public bool Login( User user, string password) {
        public string LoginError() {

            return MGLSessionSecurityInterface.Instance().SecurityError;

            //string loginError = "Invalid username or password.";

            //if (userName != null) {

            //    User user = GetUser(userName);

            //    // check the number of logins has not been exceeded
            //    if (user != null && user.IsLockedOut == true) {
            //        loginError = "The maximum number of incorrect login attempts has been exceeded - Contact the website administrator to unlock your account.";
            //    }

            //    dbInfo.Disconnect();
            //}
            //return loginError;
        }



    }
}