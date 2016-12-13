using System;
using System.Data;
using System.Configuration;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System.Web;
using System.Web.Configuration;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using MGL.Security.Email;
using System.Security;


//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for UserOperations
    /// </summary>
    internal class UserOperations : BaseSecurityOperations {

        private static string thisClassName = "MGL.GEDI.Security.UserOperations";
        private static string IS_LOGIN_USERS_BY_EMAIL_SETTING = "isLoginUsersByEmail";


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public UserOperations(ConfigurationInfo configFile)
            : base(configFile, false) {
        }


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static MGUser GuestUser {
            get {
                MGUser guest = new MGUser();
                guest.Username = Authorisation.GuestUserName;
                return guest;
            }
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This will also match on the email address
        /// (so the user can logon using either email or username)
        /// Username is tried first
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public MGUser GetUser(SecureString userName) {
            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE UserName='"
                + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt(userName).ToString()) + "';";
            string[] row = null;

            row = dbInfo.ReadLine(sqlQuery);

            if (WebConfigurationManager.AppSettings[IS_LOGIN_USERS_BY_EMAIL_SETTING] == null ||
                WebConfigurationManager.AppSettings[IS_LOGIN_USERS_BY_EMAIL_SETTING].Equals("true", StringComparison.CurrentCultureIgnoreCase)) {
                if (row == null || row.Length < 1) {
                    //Lets match on the email address  (user can enter email or username)
                    sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE Email='"
                      + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt(userName).ToString()) + "';";
                    row = dbInfo.ReadLine(sqlQuery);
                }
            }

            return BuildUserInfo(row);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This will match only on username. It will NOT match on the email address
        /// (so the user can logon using either email or username)
        /// Username is tried first
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public MGUser GetUserByUsername(SecureString userName) {
            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE UserName='"
                + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt(userName).ToString()) + "';";
            string[] row = null;

            row = dbInfo.ReadLine(sqlQuery);

            return BuildUserInfo(row);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUserByEmail(SecureString email) {
            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE Email='"
                + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt( email ).ToString()) + "';";
            string[] row = null;

            row = dbInfo.ReadLine(sqlQuery);

            return BuildUserInfo(row);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This will also match on the email address
        /// (so the user can logon using either email or username)
        /// Username is tried first
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public MGUser GetUser(SecureString emailHash, string ipAddress) {
            //string sqlQuery = "SELECT "+userFields+" FROM " + tnUsers + " WHERE MD5(Email)='"
            //    + DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(true, emailHash)
            //    + "' AND LastIP='"
            //    +DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(true, ipAddress)
            //    +"';";
            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE LastIP='"
                + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, ipAddress)
                + "';";

            string[] row = null;
            List<string[]> data = dbInfo.GetDataList(sqlQuery);
            if (data != null) {
                foreach (string[] tempRow in data) {
                    string tempEmailHash = MD5Hash.GetMd5Sum(tempRow[5]);
                    if (emailHash.Equals(tempEmailHash)) {
                        row = tempRow;
                        break;
                    }
                }
            }

            //            row = dbInfo.ReadLine(sqlQuery);

            return BuildUserInfo(row);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUser(int userID) {
            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE ID='"
                + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, userID.ToString()) + "';";
            string[] row = dbInfo.ReadLine(sqlQuery);
            return BuildUserInfo(row);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Parses the User Information from the database
        /// </summary>
        private MGUser BuildUserInfo(string[] row) {
            MGUser user = null;

            try {

                if (row != null) {
                    user = new MGUser();

                    // These are the fields ....
                    //                protected static readonly string userFields = " ID, UserName, Password, FirstName, LastName, JobTitle, Organisation, Telephone, Email, NumberOfIncorrectLogins,
                    //                TotalLogins, Description, StartDate, LastLoginDate, LastIP, LastBrowser";

                    int i = 0;
                    int tempInt = 0;

                    int.TryParse(row[i++], out tempInt);              // ID
                    user.ID = tempInt;

                    user.Username = SecureStringWrapper.Encrypt( row[i++]);                             // UserName
                    user.Password = SecureStringWrapper.Encrypt(row[i++]);                             // Password

                    // June 2013 - these are New new new NEW!
                    user.FirstName = SecureStringWrapper.Encrypt(row[i++]);                            // FirstName
                    user.LastName = SecureStringWrapper.Encrypt(row[i++]);                             // LastName

                    user.JobTitle = SecureStringWrapper.Encrypt(row[i++]);                                // JobTitle
                    user.Organisation = SecureStringWrapper.Encrypt(row[i++]);                         // Organisation
                    user.Telephone = SecureStringWrapper.Encrypt(row[i++]);                            // Telephone
                    user.Email = SecureStringWrapper.Encrypt(row[i++]);                                   // Email

                    int.TryParse(row[i++], out tempInt);            // NumberOfIncorrectLogins
                    user.NumIncorrectLogins = tempInt;

                    int.TryParse(row[i++], out tempInt);            // Total Logins ...
                    user.TotalLogins = tempInt;

                    user.Description = row[i++];                        // Description

                    // 13-Oct-2015 - bug!!  The start date was not being set - it is now ....
                    user.StartDate = DateTimeInformation.FormatDate(row[i++], true, true);  // Start Date
                    user.LastLogin = DateTimeInformation.FormatDate(row[i++], true, true);  // Last Login Date

                    user.LastIP = row[i++];                             // Last IP ...
                    user.LastBrowser = row[i++];                    // Last Browser ...
                    
                    int.TryParse(row[i++], out tempInt);            // Organisation ID ...
                    user.OrganisationID = tempInt;

                }

            } catch (Exception ex) {
                Logger.LogError(8, "Error Parsing the MGUser: " + ex.ToString());
            }

            return user;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool LogLogin(int userID, bool successful) {
            ////////////////////////////////////////
            // increment the total logins, clear the number of incorrect logins ....
            // add todays date, IP address etc ....

            if (successful) {

                dbInfo.ExecuteSQL("UPDATE " + tnUsers + " SET TotalLogins=TotalLogins+1, NumberOfIncorrectLogins=0 WHERE ID=" + userID + ";", ref successful);

                //Update other bits of info in the user table
                StringBuilder builder = new StringBuilder();

                builder.Append("UPDATE " + tnUsers + " SET LastLoginDate = '");
                builder.Append(DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString());
                builder.Append("' WHERE ID = ");
                builder.Append(userID);
                builder.Append(";");

                // Last IP
                builder.Append("UPDATE " + tnUsers + " SET LastIP = ");
                builder.Append("'");
                // 27-Nov-2015 - Converted to use this v4IPAddress method.
                builder.Append(IPAddressHelper.GetIP4OrAnyAddressFromHTTPRequest());
//                builder.Append(HttpContext.Current.Request.UserHostAddress);
                builder.Append("' ");
                builder.Append(" WHERE ID = ");
                builder.Append(userID);
                builder.Append(";");

                // Last browser
                builder.Append("UPDATE " + tnUsers + " SET LastBrowser = ");
                builder.Append("'");
                builder.Append(HttpContext.Current.Request.Browser.Browser);
                builder.Append(" ");
                builder.Append(HttpContext.Current.Request.Browser.Version);
                builder.Append("'");
                builder.Append(" WHERE ID = ");
                builder.Append(userID);
                builder.Append(";");

                dbInfo.ExecuteSQL(builder.ToString(), ref successful);

            } else {
                dbInfo.ExecuteSQL("UPDATE " + tnUsers + " SET NumberOfIncorrectLogins=NumberOfIncorrectLogins+1 WHERE ID=" + userID + ";", ref successful);
            }
            //            return ! Logger.LogList(dbInfo.GetErrors(), "UserOperations", "LogLogin");
            return successful;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UserLoginDetailsCorrect(SecureString userName, SecureString password) {
            bool success = false;
            string sqlQuery = "";
            if (Authorisation.UseMGLRatherThanMySQLPasswordEncryption) {
                // 13-Jul-2015 - This technique used to allow us to decrypt passwords for the password reminder
                // now the MGLPasswordHash is a one way encryption using salts and slow has algoriths, so we need to use the nicely rolled Compare method.

                // Get the user - with the encrypted password ...
                // This ensures that we are testing BOTH the username AND the PASSWORD in a single method ...
                MGUser user = GetUser(userName);


                //password = MGLPasswordHash.EncryptPassword(password);

                success = MGLPasswordHash.Compare(SecureStringWrapper.Decrypt(password), SecureStringWrapper.Decrypt(user.Password));

                //Do this just in case the encryption adds quotes into string - this should NEVER happen
                //password = password.Replace("'", "\\'");
                //password = password.Replace("\"", "\\\"");

                // check the user name and the encrypted password in the database
                //sqlQuery = "SELECT ID FROM " + tnUsers + " WHERE UserName='"
                 //  + DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(true, userName) + "' AND Password="
                   //+ "'" + password + "';";



            } else {
                //This is the legacy method used in Derby for e.g.
                // using MySQL password encryption

                // check the user name and the encrypted password in the database
                sqlQuery = "SELECT ID FROM " + tnUsers + " WHERE UserName='"
                    + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt(userName).ToString()) + "' AND Password="
                    + "PASSWORD( '" + DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, SecureStringWrapper.Decrypt(password).ToString()) + "');";

                List<int> userIDList = dbInfo.GetIntegerList(sqlQuery);
                if (userIDList != null && userIDList.Count == 1) {
                    success = true;
                }

            }


            return success;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<MGUser> GetAllUsers() {
            List<MGUser> users = new List<MGUser>();

            string sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + ";";

            List<string[]> data = dbInfo.GetDataList(sqlQuery);

            if (data != null) {
                foreach (string[] row in data) {
                    users.Add(BuildUserInfo(row));
                }
            }

            return users;
            //            return null;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<MGUser> GetAllUsers(List<string> fieldsToSearch, string valueToSearch, string sortColumnName, System.Web.UI.WebControls.SortDirection sortDirection) {
            string sqlQuery = "";
            sqlQuery = GetSQLForGettingAllUsers(fieldsToSearch, valueToSearch, sortColumnName, sortDirection);
            return GetListOfUsers(sqlQuery);
        }


        ////-------------------------------------------------------------------------------------------------------------------------------------------------------------
        ///// <summary>
        ///// Gets a list of MGUsers from a legacy administrator table.
        ///// The last column specified should be the password field.
        ///// </summary>
        ///// <param name="tablename">The name of the legacy administrator table.</param>
        ///// <param name="tableColumnCSV">A comma-seperated list of user columns to select to populate the MGUser object.</param>
        ///// <returns>All users in the system as list of MGUser objects.</returns>
        //public List<MGUser> GetUsersFromLegacyTable(string tablename, string tableColumnCSV) {
        //    List<MGUser> users = new List<MGUser>();
        //    string sqlQuery = "SELECT " + tableColumnCSV + " FROM " + tablename + " ORDER BY ID;";

        //    List<string[]> data = dbInfo.GetDataList(sqlQuery);

        //    if (data != null) {
        //        MGUser user = null;
        //        foreach (string[] row in data) {
        //            user = BuildUserInfo(row);
        //            user.Password = row[row.Length - 1];
        //            users.Add(user);
        //        }
        //    }

        //    return users;

        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///
        /// GetAllUsers with filter/sort parameters
        ///
        /// Default sort is by user ID
        /// </summary>
        /// <param name="filterByType"></param>
        /// <param name="filterByValue">If this is a string it will need to be enclosed in single quotes ' ' </param>
        /// <param name="sortColumnName"></param>
        /// <param name="sortDirection"></param>
        /// <returns></returns>
        public List<MGUser> GetAllUsers(string filterByType, string filterByValue, string sortColumnName, List<string> PreviousSortColumnNames, System.Web.UI.WebControls.SortDirection sortDirection) {
            string sqlQuery = "";
            string descOrAsc = "";

            string otherSortColumns = "";

            if (PreviousSortColumnNames != null && PreviousSortColumnNames.Count > 0) {
                foreach (string colName in PreviousSortColumnNames) {
                    if (colName != null)
                        otherSortColumns += " , " + colName;
                }
            }

            if (sortDirection == System.Web.UI.WebControls.SortDirection.Descending) {
                descOrAsc = " DESC ";
            }

            List<MGUser> users = new List<MGUser>();

            if (NullOrEmpty(filterByType) && NullOrEmpty(sortColumnName)) {
                sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " ORDER BY ID " + descOrAsc + otherSortColumns + ";";
            } else if (!NullOrEmpty(filterByType) && NullOrEmpty(sortColumnName)) {
                sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE " + filterByType + "=" + filterByValue + "ORDER BY ID" + descOrAsc + otherSortColumns + ";";
            } else if (!NullOrEmpty(sortColumnName) && NullOrEmpty(filterByType)) {
                sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " ORDER BY " + sortColumnName + descOrAsc + otherSortColumns + ";";
            } else if (!NullOrEmpty(filterByType) && !NullOrEmpty(sortColumnName)) {
                sqlQuery = "SELECT " + userFields + " FROM " + tnUsers + " WHERE " + filterByType + "=" + filterByValue + " ORDER BY " + sortColumnName + descOrAsc + otherSortColumns + ";";
            }

            users = GetListOfUsers(sqlQuery);

            return users;

        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        private List<MGUser> GetListOfUsers(string sqlQuery) {
            List<MGUser> result = null;
            try {
                result = new List<MGUser>();
                dbInfo.Connect();
                List<string[]> data = dbInfo.GetDataList(sqlQuery);
                if (data != null) {
                    foreach (string[] row in data) {
                        result.Add(BuildUserInfo(row));
                    }
                } else {
                    Logger.LogError(8, "Failed to read the user information from database using query = " + sqlQuery);
                }
            } catch (Exception ex) {
                Logger.LogError(8, "Error getting MG Users in a list for query : " + sqlQuery + " at: " + ex);
            } finally {
                if (dbInfo != null)
                    dbInfo.Disconnect();
            }
            return result;
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        private bool NullOrEmpty(string val) {
            return (val == null || val == "");
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<int> GetUserGroupsIDs(int userID) {
            List<int> userGroupIDs = null;
            Dictionary<int, List<int>> userUserGroupsXref = null;

            Logger.Log("Start getting groups ids for user ID = " + userID);
            try {
                userUserGroupsXref = new Dictionary<int, List<int>>();
                Logger.Log("First get the Xref for user and groups...");
                userUserGroupsXref = UserGroupDictionary("UserID=" + userID);
                if (userUserGroupsXref == null) {
                    Logger.LogError(8, "Failed to get the Xref for user and groups for user id= " + userID);
                    return null;
                }
                if (userUserGroupsXref.Count == 0) {
                    Logger.Log("No Xref for user and groups for user are found for user ID = " + userID);
                    return new List<int>();
                }
                userGroupIDs = new List<int>();

                List<int> groupIDs = null;
                foreach (int id in userUserGroupsXref.Keys) {
                    groupIDs = userUserGroupsXref[id];
                    userGroupIDs.AddRange(groupIDs);
                }
            } catch (Exception ex) {
                Logger.LogError(8, "Error getting groups ids for user ID = " + userID + " at " + ex);
                return null;
            }
            return userGroupIDs;
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public Dictionary<int, List<int>> UserGroupDictionary() {
            string whereClause = null;
            return UserGroupDictionary(whereClause);
        }

        public Dictionary<int, List<int>> UserGroupDictionary(string whereClause) {

            Dictionary<int, List<int>> result = null;
            StringBuilder builder = new StringBuilder();
            builder.Append("SELECT UserID, GroupID FROM " + tnXrefGroupsUsers);
            if (whereClause != null) {
                builder.Append(" WHERE ");
                builder.Append(whereClause);
            }
            builder.Append(";");
            string sql = builder.ToString();

            try {
                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null) {
                    Logger.LogError(5, "Error getting user and group information for sql: " + sql);
                    return null;
                } else if (data.Count == 0) {
                    Logger.Log("No record was found in the database for sql :" + sql);
                    return new Dictionary<int, List<int>>();
                }
                Logger.Log("Start building the user group dictionary.");
                result = BuildXrefDictionary(data);
                if (result == null) {
                    Logger.LogError(5, "Error, got Null user group dictionary. Quitting!");
                    return null;
                } else if (result.Count == 0) {
                    Logger.LogError(5, "Error, got Empty user group dictionary. Quitting!");
                    return null;
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting User Group Dictionary at: " + ex);
                return null;
            }
            return result;


            //return BuildXrefDictionary(data);
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public Dictionary<int, MGUser> UserDictionary() {
            Dictionary<int, MGUser> userDict = null;

            List<MGUser> allUsers = GetAllUsers();
            if (allUsers != null) {
                userDict = new Dictionary<int, MGUser>();
                try {
                    foreach (MGUser user in allUsers) {
                        userDict.Add(user.ID, user);
                    }
                } catch (Exception ex) {
                    Logger.LogError(5, thisClassName + " UserDictionary: " + ex.ToString());
                }
            }
            return userDict;
        }



        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public DateTime GetPasswordChangeDate(int userID) {
            CheckForPasswordChangeDateColumn();
            DateTime result = DateTime.MinValue;
            try {

                string sqlQuery = "SELECT " + PasswordChangeDateCol + "," + StartDateCol + " FROM " + tnUsers + " WHERE ID = " + userID + ";";

                string[] data = dbInfo.GetDataSingleRecord(sqlQuery);

                bool foundDate = false;

                if (data != null && data.Length == 2) {
                    if (data[0] != null) {
                        foundDate = DateTime.TryParse(data[0], out result);
                    }

                    if (!foundDate && data[1] != null) {
                        foundDate = DateTime.TryParse(data[1], out result);
                    }

                    if (!foundDate) {
                        result = DateTime.MinValue;
                    }
                } else {
                    throw new Exception("Error trying to GetPasswordChangeDate from users table. SQL:" + sqlQuery);
                }
            } catch (Exception ex) {
                Logger.LogError(8, ex.Message);
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        private string GetSQLForGettingAllUsers(List<string> searchFields, string searchString, string sortColumnName, System.Web.UI.WebControls.SortDirection sortDirection) {
            string whereClause = string.Empty;
            string descOrAsc = "";
            if (sortDirection == System.Web.UI.WebControls.SortDirection.Descending) {
                descOrAsc = " DESC ";
            }

            StringBuilder sql = new StringBuilder();
            sql.Append("SELECT " + userFields + " FROM " + tnUsers + " ");


            //If the search field list is not null then create a Where Clause
            if (searchFields != null && searchFields.Count > 0 && !NullOrEmpty(searchString)) {
                whereClause = " WHERE ";
                int totoalMembers = searchFields.Count;
                int i = 1;
                foreach (string fieldName in searchFields) {
                    whereClause += fieldName + " LIKE '%" + searchString + "%'";
                    if (totoalMembers != i) {
                        whereClause += " OR ";
                    }
                    i++;
                    //WHERE UserName like '%hartley%' or JobTitle like '%hartley%' or Email like '%hartley%'
                }
            }

            if (whereClause != null && whereClause != string.Empty) {
                sql.Append(whereClause);
            }
            sql.Append("ORDER BY ");
            if (NullOrEmpty(sortColumnName)) {
                sql.Append(" ID ");
            } else {
                sql.Append(sortColumnName);
            }
            sql.Append(descOrAsc);
            sql.Append(";");

            return sql.ToString();
        }
    }
}