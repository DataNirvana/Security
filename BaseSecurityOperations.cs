using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Configuration;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using MGL.Security.Email;
using System.Security;
using System.Text;
using DataNirvana.Database;
//using MGL.LLPG;


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
/// <summary>
/// Summary description for UserAdminDAL
/// </summary>
namespace MGL.Security {

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>Public so that it can be used by RuleBuilder too</summary>
    public class BaseSecurityOperations {

        private static string thisClassName = "MGL.GEDI.Security.BaseSecurityOperations";

        protected DatabaseWrapper dbInfo;
        protected ConfigurationInfo lcf;

        public static readonly string tnUsers = "Security_Users";
        public static readonly string tnGroups = "Security_Groups";
        public static readonly string tnFunctionality = "Security_Functionality";
        public static readonly string tnDisplay = "Security_Display";
        public static readonly string tnContent = "Security_Content";

        public static readonly string tnXrefGroupsUsers = "Security_Xref_Group_User";
        public static readonly string tnXrefGroupsFunctionality = "Security_Xref_Group_Functionality";
        public static readonly string tnXrefGroupsDisplay = "Security_Xref_Group_Display";
        public static readonly string tnXrefGroupsContent = "Security_Xref_Group_Content";

        // No point getting the password as its encrypted now ...
        protected static readonly string userFields =
            "ID, UserName, Password, FirstName, LastName, JobTitle, Organisation, Telephone, Email, NumberOfIncorrectLogins, TotalLogins, Description, StartDate, LastLoginDate, LastIP, LastBrowser, info_organisations_id";


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public BaseSecurityOperations(ConfigurationInfo LCF) {
            // ALWAYS check the Password Field Length
            DoStart(LCF, true);
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public BaseSecurityOperations(ConfigurationInfo LCF, bool checkPasswordFieldLength) {
            DoStart(LCF, checkPasswordFieldLength);
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        private void DoStart(ConfigurationInfo LCF, bool checkPasswordFieldLength) {
            lcf = LCF;

            dbInfo = new DatabaseWrapper(lcf);
            dbInfo.Connect();

            if (checkPasswordFieldLength == true) {
                CheckPasswordFieldLength();
            }
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// We need to make sure the password
        /// field is long enough to fit the new mgl encrypted passwords
        /// (these should be a max of 128 bits, but lets use 256 just incase!)
        /// </summary>
        protected void CheckPasswordFieldLength() {
            if (!MGLApplicationSecurityInterface.Instance().PasswordFieldLengthChecked) {
                //We need to make sure the password
                //field is long enough to fit the new mgl encrypted passwords
                // (these should be a max of 128 bits, but lets use 256 just incase!)
                string sql = "";
                try {
                    dbInfo.Connect();

                    string requiredVarType = "VARCHAR(255)";

                    string type = dbInfo.GetColumnType(tnUsers, "Password");

                    if (type.ToLower() != requiredVarType.ToLower()) {
                        sql = "ALTER TABLE " + tnUsers + @" MODIFY COLUMN `Password` " + requiredVarType + ";";

                        bool success = false;
                        dbInfo.ExecuteSQL(sql, ref success);
                    }

                    MGLApplicationSecurityInterface.Instance().PasswordFieldLengthChecked = true;
                } catch (Exception e) {
                    Logger.LogError(8, "Error trying to set the users table password column length to 255. " + sql + ". " + e.StackTrace);
                } finally {
                    dbInfo.Disconnect();
                }
            }
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public void Finish() {
            dbInfo.Disconnect();
        }



        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string GetXrefTableName(string featureClass) {
            string tn = null;
            if (featureClass != null) {
                if (featureClass.ToLower().Equals(SecurityFeatureClasses.Content)) {
                    tn = BaseSecurityOperations.tnXrefGroupsContent;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Functionality)) {
                    tn = BaseSecurityOperations.tnXrefGroupsFunctionality;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Display)) {
                    tn = BaseSecurityOperations.tnXrefGroupsDisplay;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.User)) {
                    tn = BaseSecurityOperations.tnXrefGroupsUsers;
                } else {
                    Logger.LogError(5, thisClassName + " GetXrefTableName: Unknown feature class provided: '" + featureClass + "' ");
                }
            }
            return tn;
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string GetXrefColumnName(string featureClass) {
            string featureCN = "FeatureID";
            if (featureClass != null) {
                if (featureClass.ToLower().Equals(SecurityFeatureClasses.Content)) {
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Functionality)) {
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Display)) {
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.User)) {
                    featureCN = "UserID";
                } else {
                    Logger.LogError(5, thisClassName + " GetXrefTableName: Unknown feature class provided: '" + featureClass + "'");
                }
            }
            return featureCN;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string GetSourceTableName(string featureClass) {
            string tn = null;
            if (featureClass != null) {
                if (featureClass.ToLower().Equals(SecurityFeatureClasses.Content)) {
                    tn = BaseSecurityOperations.tnContent;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Functionality)) {
                    tn = BaseSecurityOperations.tnFunctionality;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.Display)) {
                    tn = BaseSecurityOperations.tnDisplay;
                } else if (featureClass.ToLower().Equals(SecurityFeatureClasses.User)) {
                    tn = BaseSecurityOperations.tnUsers;
                } else {
                    Logger.LogError(5, thisClassName + " GetSourceTableName Unknown feature class provided: '" + featureClass + "'");
                }
            }
            return tn;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>The given List<string[]> is assumed to contain int, int and the first int is the key ...</summary>
        public Dictionary<int, List<int>> BuildXrefDictionary(List<string[]> data) {
            Dictionary<int, List<int>> dict = null;

            if (data != null) {
                dict = new Dictionary<int, List<int>>();

                try {
                    foreach (string[] row in data) {
                        int myKey = int.Parse(row[0]);
                        int myVal = int.Parse(row[1]);

                        if (dict.ContainsKey(myKey)) {
                            try {
                                List<int> values = null;
                                dict.TryGetValue(myKey, out values);
                                if (values.Contains(myVal) == false) {
                                    dict.Remove(myKey);
                                    values.Add(myVal);
                                    dict.Add(myKey, values);
                                }
                            } catch { }
                        } else {
                            List<int> values = new List<int>();
                            values.Add(myVal);
                            dict.Add(myKey, values);
                        }

                    }
                } catch (Exception ex) {
                    Logger.LogError(5, "Problem building xref dictionary at " + ex.StackTrace);
                    return null;
                }
            }
            return dict;
        }

        public Dictionary<int, List<MGSecurityTag>> BuildSecurityDictionary(List<string[]> data) {
            bool isCheckForUniqVals = true;
            return BuildSecurityDictionary(data, isCheckForUniqVals);
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>The given List<string[]> is assumed to contain int, string, int and the first int is the key ...</summary>
        public Dictionary<int, List<MGSecurityTag>> BuildSecurityDictionary(
            List<string[]> data,
            bool isCheckForUniqVals) {
            Dictionary<int, List<MGSecurityTag>> dict = null;

            if (data != null) {
                dict = new Dictionary<int, List<MGSecurityTag>>();

                try {
                    foreach (string[] row in data) {
                        int myKey = int.Parse(row[0]);
                        // All tags are compared in lower case
                        MGSecurityTag myVal = new MGSecurityTag(row[1].ToLower(), int.Parse(row[2]));

                        if (row.Length > 3 && row[3] != null && row[3] != String.Empty) {
                            int id = -1;
                            if (int.TryParse(row[3], out id)) {
                                myVal.ID = id;
                            }
                        }

                        if (row.Length > 4) {
                            myVal.Description = row[4];
                        }

                        if (dict.ContainsKey(myKey)) {
                            try {
                                List<MGSecurityTag> values = null;

                                dict.TryGetValue(myKey, out values);

                                if (!isCheckForUniqVals && values != null) {
                                    values.Add(myVal);
                                } else if (values.Contains(myVal) == false) {
                                    dict.Remove(myKey);
                                    values.Add(myVal);
                                    dict.Add(myKey, values);
                                }
                            } catch { }
                        } else {
                            List<MGSecurityTag> values = new List<MGSecurityTag>();
                            values.Add(myVal);
                            dict.Add(myKey, values);
                        }
                    }
                } catch (Exception ex) {
                    Logger.LogError(5, "Problem building BuildSecurityDictionary at " + ex.StackTrace);
                    dict = null;
                }
            }


            return dict;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool CreateSecurityXrefTable(bool isUserGroupXref, string tn) {
            bool success = false;

            string otherCol = (isUserGroupXref) ? "UserID" : "FeatureID";
            string tableParams = "GroupID INT, INDEX( GroupID ), " + otherCol + " INT, INDEX( " + otherCol + ")";
            if (isUserGroupXref) {
                tableParams = tableParams + ", PRIMARY KEY( GroupID, " + otherCol + ")";
            }

            success = dbInfo.CreateTable(tn, tableParams, false);
            if (success == false) {
                Logger.LogError(9, "Failed to create table in CreateSecurityXrefTable!");
                //                Logger.LogList(dbInfo.GetErrors(), thisClassName, "CreateSecurityXrefTable");
            }

            return success;
        }



        ////-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public DataTable GetUserDetail(object userID)
        //{
        //    DataTable theTable = GetUserDetailSQL(userID);

        //    //Should only have 1 row
        //    if (theTable.Rows.Count == 1)
        //    {
        //        //hide the password
        //        DataRow dr = theTable.Rows[0];
        //        dr["Password"] = "";
        //    }

        //    return theTable;
        //}

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public DataTable GetBlankUserDetail()
        //{
        //    User theUser = new User(1);
        //    DataTable theTable = GetUserDetailSQL(theUser);

        //    //Should only have 1 row
        //    if (theTable.Rows.Count == 1)
        //    {
        //        //hide the password
        //        DataRow dr = theTable.Rows[0];
        //        dr["Password"] = "";
        //    }

        //    return theTable;
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public int UpdateUser(string Username, string UserType, string Email, string Password, string JobTitle, string Organisation, string Telephone, string UserId)
        //{
        //    return UpdateUserSQL(Username, UserType, Email, Password, JobTitle, Organisation, Telephone, UserId);
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public int InsertNewUser(string Username, string UserType, string Email, string Password, string JobTitle, string Organisation, string Telephone)
        //{
        //    return InsertUserSQL(Username, UserType, Email, Password, JobTitle, Organisation, Telephone);
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public int DeleteUser(User user)
        //{
        //    int result = 0;
        //    try
        //    {
        //        Database.Connect();

        //        string sql = "DELETE FROM administrator where UserId = " + user.UserID;

        //        result = Database.ExecuteSQL(sql);

        //    }
        //    catch (Exception e)
        //    {
        //    }
        //    finally
        //    {
        //        Database.Disconnect();
        //    }

        //    return result;
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        public List<User> GetAllEnums()
        //        {
        ////            Array userTypes = Enum.GetValues(typeof(MGL.Common.DomainModel.Security.User.UserTypeEnum));

        //            bool hideAdmin = false;

        //            //If the current user in not Administrator then hide the Admin option
        //            if (! MGLSessionInterface.Instance().CurrentUser.IsAdmin)
        //            {
        //                hideAdmin = true;
        //            }

        //            bool hideSecure = true;

        //            //If the system does NOT have a secure database then hide the secure option
        //            if (MGL.Common.DataLayer.Config.LoginConfig.Instance.UseSecureDBOnLogin)
        //            {
        //                hideSecure = false;
        //            }

        //            List<User> userList = new List<User>();
        //            foreach (User.UserTypeEnum uType in userTypes)
        //            {
        //                if (!hideAdmin || uType != User.UserTypeEnum.admin)
        //                {
        //                    if (hideSecure && uType == User.UserTypeEnum.secure)
        //                    {
        //                        //Dont add this uType
        //                    }
        //                    else
        //                    {
        //                        User user = new User();
        //                        user.UserType = uType;
        //                        userList.Add(user);
        //                    }
        //                }

        //            }


        //            return userList;
        //        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //public User.UserTypeEnum GetRowUserType(string userID)
        //{
        //    User.UserTypeEnum result = User.UserTypeEnum.user;

        //    try
        //    {
        //        DataTable dt = GetUserDetailSQL(userID);

        //        if (dt.Rows.Count == 1)
        //        {
        //            //hide the password
        //            DataRow dr = dt.Rows[0];
        //            result = User.GetUserEnum(dr["UserType"].ToString());

        //        }
        //    }
        //    catch
        //    {
        //    }

        //    return result;
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        public bool UserNameOK(string userName)
        //        {
        //            //Default to false to ensure we dont
        //            //try to insert user with the same name
        //            //if they already exist
        //            bool result = false;

        //            try
        //            {
        //                Database.Connect();

        //                string sql = @"SELECT *
        //                              FROM administrator
        //                              WHERE UserName = '" + userName + "'";

        //                IDataReader myReader = Database.RunSqlReader(sql);

        //                if (myReader != null && myReader.Read())
        //                {
        //                    result = false;
        //                }
        //                else
        //                {
        //                    //Weve not found the name so should be ok to use it
        //                    result = true;
        //                }

        //            }
        //            catch (Exception e)
        //            {
        //            }
        //            finally
        //            {
        //                Database.Disconnect();
        //            }

        //            return result;

        //        }

        ////////////////
        //        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        private DataTable getAllUsers()
        //        {
        //            DataTable dataTable = new DataTable();

        //            try
        //            {
        //                Database.Connect();

        //                string sql = @"SELECT
        //                                UserID,
        //                                UserName,
        //                                UserType,
        //                                Password,
        //                                LastLogin,
        //                                JobTitle,
        //                                Organisation,
        //                                Telephone,
        //                                Email,
        //                                NumberOfIncorrectLogins
        //                              FROM administrator";

        //                IDataReader myReader = Database.RunSqlReader(sql);

        //                dataTable.Load(myReader);

        //            }
        //            catch (Exception e)
        //            {
        //            }
        //            finally
        //            {
        //                Database.Disconnect();
        //            }

        //            return dataTable;
        //        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        private DataTable GetUserDetailSQL(object userID)
        //        {

        //            DataTable dataTable = new DataTable();

        //            try
        //            {
        //                string theID = userID.ToString();

        //                Database.Connect();

        //                string sql = @"SELECT
        //                    UserID,
        //                    UserName,
        //                    UserType,
        //                    Password,
        //                    LastLogin,
        //                    JobTitle,
        //                    Organisation,
        //                    Telephone,
        //                    Email,
        //                    NumberOfIncorrectLogins
        //                  FROM administrator where UserId =" + theID;

        //                IDataReader myReader = Database.RunSqlReader(sql);

        //                dataTable.Load(myReader);

        //            }
        //            catch (Exception e)
        //            {
        //            }
        //            finally
        //            {
        //                Database.Disconnect();
        //            }

        //            return dataTable;
        //        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        //        private int UpdateUserSQL(string Username, string UserType, string Email, string Password, string JobTitle, string Organisation, string Telephone, string UserId)
        //        {
        //            int result = 0;
        //            try
        //            {
        //                Database.Connect();

        //                string strPwd = "";

        //                //Only add password if it is not null.
        //                if (Password != null && Password != String.Empty)
        //                {
        //                    strPwd =  "Password = '" + Password + "',";
        //                }

        //                string sql = @"UPDATE administrator SET
        //                                UserName= '" + Username + @"',
        //                                UserType = '" + UserType + @"',
        //                                " + strPwd + @"
        //                                JobTitle = '" + JobTitle + @"',
        //                                Organisation = '" + Organisation + @"',
        //                                Telephone = '" + Telephone + @"',
        //                                Email = '" + Email + @"'
        //                            WHERE administrator.UserID =  " + UserId;

        //                result = Database.ExecuteSQL(sql);

        //            }
        //            catch (Exception e)
        //            {
        //            }
        //            finally
        //            {
        //                Database.Disconnect();
        //            }

        //            return result;
        //        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool InsertUser(MGUser newUser) {
            bool isInserted = false;

            isInserted = InsertUser(newUser.Username, newUser.Email, newUser.Password, newUser.JobTitle, 
                newUser.Organisation, newUser.OrganisationID, newUser.Telephone);

            if (!isInserted) {
                Logger.LogError(9, "Failed to insert new user with username " + newUser.Username);
            }

            return isInserted;
        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool InsertUser(SecureString Username, SecureString Email, SecureString Password, SecureString JobTitle, SecureString OrganisationAcronym, int OrganisationID, SecureString Telephone) {
            return InsertUser(Username, Email, Password, JobTitle, OrganisationAcronym, OrganisationID, Telephone, tnUsers);
        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool InsertUser(SecureString Username, SecureString Email, SecureString Password, SecureString JobTitle, SecureString OrganisationAcronym, int OrganisationID, SecureString Telephone,
            string userTable) {

                return InsertUser(new SecureString(), new SecureString(),
                    Username, Email, Password, JobTitle, OrganisationAcronym, OrganisationID, Telephone, userTable, Authorisation.UseMGLRatherThanMySQLPasswordEncryption);

        }
        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool InsertUser(
            SecureString firstName, SecureString lastName,
            SecureString Username, SecureString Email, SecureString Password,
            SecureString JobTitle, SecureString OrganisationAcronym, int OrganisationID, SecureString Telephone,
            string userTable,
            bool useMGLRatherThanMySQLPasswordEncryption) {

            bool result = false;
            try {
                dbInfo.Connect();

                //firstName = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, firstName, false);
                //lastName = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, lastName, false);

                //Username = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Username, false);
                //Email = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Email, false);
                //Password = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Password, false);
                //JobTitle = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, JobTitle, false);
                //Organisation = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Organisation, false);
                //Telephone = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Telephone, false);

                string StartDate = DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString();

                StringBuilder sql = new StringBuilder();

                sql.Append("INSERT INTO " + userTable + "(");
                sql.Append("FirstName, LastName, UserName, Password, JobTitle, Organisation, info_organisations_id, Telephone, Email, StartDate");
                sql.Append(") Values (");

                // Databaseify string combines the quoting and the SQL Injection check to make our lives eeeeeeaaaassssyyyyy

                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(firstName).ToString())); // Firstname
                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(lastName).ToString())); // LastName
                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Username).ToString(), false, true)); // UserName (not null)
                sql.Append(", ");


                if (useMGLRatherThanMySQLPasswordEncryption) {
                    // 13-Jul-2015 - replaced the two way encryption with password hashing which is deemed best practise at the moment (although there can therefore be no password reminders, only a reset)
                    // password is hashed as base64 so there is no possibility of there being quotes in it !!
                    sql.Append("'" + MGLPasswordHash.EncryptPassword(Password) + "'");
                } else {
                    //This is the legacy method used in Derby using MySQL password encryption
                    sql.Append("PASSWORD('" + SecureStringWrapper.Decrypt(DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, Password, false)) + "')");
                }

                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(JobTitle).ToString())); // Job Title
                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(OrganisationAcronym).ToString(), false, true)); // Organisation Acronym (not null)
                sql.Append(", ");
                sql.Append(OrganisationID); // Organisation ID (not null)
                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Telephone).ToString(), false, true)); // Telephone (not null)
                sql.Append(", ");
                sql.Append(DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Email).ToString(), false, true)); // Email (not null)
                sql.Append(", ");
                sql.Append(DataUtilities.Quote(StartDate)); // StartDate

                sql.Append(");");
                bool success = false;
                if (dbInfo.ExecuteSQL(sql.ToString(), ref success) == 1) {
                    result = true;
                }

            } catch (Exception ex) {
                Logger.LogError(9, "Failed to insert user with username " + Username + " at " + ex.StackTrace);
                result = false;
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UpdateUserDetails(int UserID, SecureString Username, SecureString Email, SecureString JobTitle, SecureString OrganisationAcronym, int OrganisationID, SecureString Telephone) {
//            bool result = false;
//            try {

                return UpdateUserDetails(UserID, null, null, Username, Email, JobTitle, OrganisationAcronym, OrganisationID, Telephone);

//                dbInfo.Connect();

//                Username = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Username, false);
//                Email = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Email, false);

//                JobTitle = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, JobTitle, false);
//                Organisation = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Organisation, false);
//                Telephone = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Telephone, false);

//                //ss: 23rd Nov 2010:
//                // WHO PUT THIS IN?!?!? StartDate should only be updated when a user is added into the system!
//                // the clue is in the name!!!
//                // string StartDate = DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString();


//                //                string sql = @"UPDATE " + tnUsers + @"
//                //                                SET UserName = '" + Username + @"',
//                //                                JobTitle = '" + JobTitle + @"',
//                //                                Organisation = '" + Organisation + @"',
//                //                                Telephone = '" + Telephone + @"',
//                //                                Email = '" + Email + @"',
//                //                                StartDate = '" + StartDate + @"'
//                //                               WHERE id = " + UserID + ";";

//                string sql = @"UPDATE " + tnUsers + @"
//                                SET UserName = '" + SecureStringWrapper.Decrypt( Username ) + @"',
//                                JobTitle = '" + SecureStringWrapper.Decrypt( JobTitle ) + @"',
//                                Organisation = '" + SecureStringWrapper.Decrypt( Organisation ) + @"',
//                                Telephone = '" + SecureStringWrapper.Decrypt( Telephone ) + @"',
//                                Email = '" + SecureStringWrapper.Decrypt( Email ) + @"'
//                               WHERE id = " + UserID + ";";

//                bool success = false;
//                if (dbInfo.ExecuteSQL(sql, ref success) == 1) {
//                    result = true;
//                }
//            } catch (Exception ex) {
//                Logger.LogError("Failed in UpdateUserDetails at " + ex.StackTrace);
//                return false;
//            } finally {
//                dbInfo.Disconnect();
//            }

//            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UpdateUserDetails(
            int UserID, SecureString firstName, SecureString lastName, SecureString Username, SecureString Email,
            SecureString JobTitle, SecureString OrganisationAcronym, int OrganisationID, SecureString Telephone) {

            bool result = false;

            try {
                dbInfo.Connect();

                //firstName = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, firstName, false);
                //lastName = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, lastName, false);

                //Username = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Username, false);
                //Email = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Email, false);

                //JobTitle = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, JobTitle, false);
                //Organisation = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Organisation, false);
                //Telephone = DatabaseInformation.SQL_INJECTION_CHECK_PARAMETER(false, Telephone, false);

                //ss: 23rd Nov 2010:
                // WHO PUT THIS IN?!?!? StartDate should only be updated when a user is added into the system!
                // the clue is in the name!!!
                // string StartDate = DateTimeInformation.GetUniversalDateTime(DateTime.Now).ToString();
                StringBuilder sql = new StringBuilder();
                sql.Append("UPDATE " + tnUsers + " SET ");

                // Databaseify string combines the quoting and the SQL Injection check to make our lives eeeeeeaaaassssyyyyy
                sql.Append("FirstName = " + DataUtilities.DatabaseifyString( SecureStringWrapper.Decrypt( firstName ).ToString()));
                sql.Append( ", " );
                sql.Append("LastName = " + DataUtilities.DatabaseifyString( SecureStringWrapper.Decrypt( lastName ).ToString()));
                sql.Append( ", " );
                sql.Append("UserName = " + DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Username).ToString(), false, true)); // (not null)
                sql.Append( ", " );
                sql.Append("JobTitle = " + DataUtilities.DatabaseifyString( SecureStringWrapper.Decrypt( JobTitle ).ToString()));
                sql.Append( ", " );
                sql.Append("Organisation = " + DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(OrganisationAcronym).ToString(), false, true)); // (not null)
                sql.Append( ", " );
                sql.Append("info_organisations_id = " + OrganisationID); // (not null)
                sql.Append(", ");
                sql.Append("Telephone = " + DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Telephone).ToString(), false, true)); // (not null)
                sql.Append( ", " );
                sql.Append("Email = " + DataUtilities.DatabaseifyString(SecureStringWrapper.Decrypt(Email).ToString(), false, true)); // (not null)
                sql.Append(" ");
                sql.Append("WHERE id = " + UserID + ";");

                bool success = false;
                if (dbInfo.ExecuteSQL(sql.ToString(), ref success) == 1) {
                    result = true;
                }
            } catch (Exception ex) {
                Logger.LogError(9, "Failed in UpdateUserDetails at " + ex.StackTrace);
                return false;
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }




        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Updated to use the new one way passwords (13-July-2015)
        /// </summary>
        public bool UpdateUserPassword(int UserID, SecureString Password, bool useMGLRatherThanMySQLPasswordEncryption) {
            bool result = false;
            try {
                dbInfo.Connect();

                Password = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, Password, false);

                StringBuilder PasswordStr = new StringBuilder();
                if (useMGLRatherThanMySQLPasswordEncryption) { //Authorisation.UseMGLRatherThanMySQLPasswordEncryption)

                    // 13-Jul-2015 - This technique does NOT allow us anymore to decrypt passwords for the password reminder
                    PasswordStr.Append( "'" + MGLPasswordHash.EncryptPassword(Password) + "'" );
                } else {
                    //This is the legacy method used in Derby using MySQL password encryption
                    //PasswordStr = "PASSWORD('" + Password + "')";
                    PasswordStr.Append("PASSWORD('" + SecureStringWrapper.Decrypt(Password) + "')");
                }

                string sql = @"UPDATE " + tnUsers + @"
                                SET
                                Password = " + PasswordStr + @"
                                WHERE id = " + UserID + ";";

                bool success = false;
                if (dbInfo.ExecuteSQL(sql, ref success) == 1) {
                    result = true;
                }
            } catch (Exception ex) {
                Logger.LogError(9, "Failed in UpdateUserPassword at " + ex.StackTrace);
                return false;
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool DeleteUser(int userID) {
            bool result = true;
            try {
                dbInfo.Connect();

                //Delete from main users table
                string sql = "DELETE FROM " + tnUsers + " WHERE ID = " + userID + ";";

                bool success = false;
                if (dbInfo.ExecuteSQL(sql, ref success) != 1) {
                    result = false;
                }
            } catch (Exception ex) {
                Logger.LogError(9, "Failed to DeleteUser with user ID " + userID + " at " + ex.StackTrace);
                result = false;
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool DeleteUsersGroupXrefs(int userID) {
            bool result = true;
            try {
                dbInfo.Connect();

                //Delete from xrefs table
                string sql = "DELETE FROM " + tnXrefGroupsUsers + " WHERE UserID = " + userID + ";";

                bool success = false;
                if (dbInfo.ExecuteSQL(sql, ref success) < 0) {
                    result = false;
                }
            } catch (Exception ex) {
                Logger.LogError(9, "Failed to DeleteUsersGroupXrefs with user ID " + userID + " at " + ex.StackTrace);
                result = false;
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UserNameAlreadyExists(SecureString Username) {
            //Default to false to ensure we dont
            //try to insert user with the same name
            //if they already exist
            bool result = false;
            IDataReader myReader = null;
            try {
                dbInfo.Connect();

                // Escaping of e.g quotes is done here ...
                Username = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, Username, false);

                string sql = @"SELECT *
                              FROM " + tnUsers + @"
                              WHERE UserName = '"
                              + SecureStringWrapper.Decrypt( Username ) + "';";

                myReader = dbInfo.RunSqlReader(sql);

                if (myReader != null && myReader.Read()) {
                    result = true;
                } else {
                    //Weve not found the name so should be ok to use it
                    result = false;
                }

                myReader.Close();

            } catch (Exception ex) {
                Logger.LogError(9, "Failed in UserNameAlreadyExists at " + ex.StackTrace);
                try {
                    myReader.Close();
                } catch {
                }
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool EmailAlreadyExists(SecureString emailAddress) {
            //Default to false to ensure we dont
            //try to insert user with the same emailAddress
            bool result = false;
            IDataReader myReader = null;
            try {
                dbInfo.Connect();

                // Escaping of e.g quotes is done here ...
                emailAddress = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, emailAddress, false);

                string sql = @"SELECT *
                              FROM " + tnUsers + @"
                              WHERE Email = '" + SecureStringWrapper.Decrypt( emailAddress ) + "'";

                myReader = dbInfo.RunSqlReader(sql);

                if (myReader != null && myReader.Read()) {
                    result = true;
                } else {
                    //Weve not found the name so should be ok to use it
                    result = false;
                }

                myReader.Close();

            } catch (Exception ex) {
                Logger.LogError(9, "Failed in EmailAlreadyExists at " + ex.StackTrace);

                try {
                    myReader.Close();
                } catch {
                }
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UpdateUserToGroupXref(SecureString Username, MGGroupType groupType) {
            bool result = false;
            string sql = "";
            try {
                dbInfo.Connect();

                Username = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, Username, false);

                sql = @"INSERT INTO " + tnXrefGroupsUsers + @" (UserID, GroupID)
                                VALUE (
                                (SELECT ID FROM " + tnUsers + " WHERE UserName = '" + SecureStringWrapper.Decrypt( Username ) + @"'),
                                (SELECT ID FROM " + tnGroups + " WHERE GroupName = '" + groupType.ToString() + "'));";

                bool success = false;
                if (dbInfo.ExecuteSQL(sql, ref success) == 1) {
                    return true;
                }

            } catch (Exception ex) {
                Logger.LogError(9, "Failed in UpdateUserToGroupXref at " + ex.StackTrace);
                Logger.Log("The was an error in UpdateUserToGroupXref(). (" + sql + ") " + ex.Message);
            } finally {
                dbInfo.Disconnect();
            }

            return result;
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public static readonly string INSERT_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public void UpdatePasswordChangeDate(int userID, DateTime timeStamp) {
            try {
                CheckForPasswordChangeDateColumn();
                //                DateTime result = DateTime.MinValue;

                string sqlQuery = "UPDATE " + tnUsers + " SET " + PasswordChangeDateCol + "='" + timeStamp.ToString(INSERT_DATE_FORMAT) + "' WHERE ID = " + userID + ";";

                bool success = false;
                if (dbInfo.ExecuteSQL(sqlQuery, ref success) != 1) {
                    throw new Exception("Failed to update the PasswordChangeDateCol for a user. sql:" + sqlQuery);
                }
            } catch (Exception ex) {
                Logger.LogError(9, "Failed in UpdatePasswordChangeDate at " + ex.StackTrace);
                Logger.LogError(9, ex.Message);
            } finally {
                dbInfo.Disconnect();
            }
        }

        //-----------------------------------------------------------------------------------------------------------------------------------------------------------
        public void UpdatePasswordChangeDate(SecureString userName, DateTime timeStamp) {
            try {
                CheckForPasswordChangeDateColumn();
                //                DateTime result = DateTime.MinValue;

                userName = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(false, userName, false);

                string sqlQuery = "UPDATE " + tnUsers + " SET " + PasswordChangeDateCol + "='" + timeStamp.ToString(INSERT_DATE_FORMAT)
                    + "' WHERE UserName = '" + SecureStringWrapper.Decrypt( userName ) + "';";

                bool success = false;
                if (dbInfo.ExecuteSQL(sqlQuery, ref success) != 1) {
                    throw new Exception("Failed to update the PasswordChangeDateCol for a user. sql:" + sqlQuery);
                }
            } catch (Exception ex) {
                Logger.LogError(8, "Failed in UpdatePasswordChangeDate at " + ex.StackTrace);
                Logger.LogError(8, ex.Message);
            } finally {
                dbInfo.Disconnect();
            }
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        public string PasswordChangeDateCol = "PasswordChangeDate";
        public string StartDateCol = "StartDate";
        public void CheckForPasswordChangeDateColumn() {
            try {
                if (!dbInfo.ColumnExists(tnUsers, PasswordChangeDateCol)) {
                    dbInfo.AddColumn(tnUsers, PasswordChangeDateCol, "DATETIME");
                }
            } catch (Exception ex) {
                Logger.LogError(8, "Failed in CheckForPasswordChangeDateColumn at " + ex.StackTrace);
                Logger.LogError(8, ex.Message);
            } finally {
                dbInfo.Disconnect();
            }
        }




        //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UnlockUser(int userID) {
            bool success = false;

            try {
                string sql = UserAdministration.GetUnlockUserSql(userID.ToString());

                dbInfo.ExecuteSQL(sql, ref success);

            } catch (Exception ex) {
                Logger.LogError(8, "Failed to unlock the Users password " + ex.StackTrace);
                Logger.LogError(8, ex.Message);
            } finally {
                dbInfo.Disconnect();
            }

            return success;
        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Make the whole system a bit more user friendly ....
        /// </summary>
        public bool PasswordChangedEmailUser(MGUser u, DateTime timeStamp, bool useHttps) {
            bool success = false;

            string httpPrefix = (useHttps == true) ? "https" : "http";
                // 12-Oct-2015 - BUG BUG BUG - cannot use the application or session variables in THREADED code - ie code that is running in a separate thread ...
                //(MGLApplicationSecurityInterface.Instance().AppLoginConfig.UseHTTPS == true) ? "https" : "http";

            // 25-Nov-2015 - localise the dates
            string prettyLocalDate = "";
            success = LocaliseTime.Localise(lcf, timeStamp, 3, u.ID, out prettyLocalDate);

            // Send an email
            string messageBody =
                "<p style='font-family: Trebuchet MS;'>"
                    + "Hi " + SecureStringWrapper.Decrypt( u.FirstName ) + ", "
                    + "<br /><br />"
                    + "Your password for <b>" + Authorisation.ApplicationName
                    + "</b> was updated on <b>" + prettyLocalDate
                     //DateTimeInformation.PrettyDateTimeFormat(timeStamp, this.timezoneOffset)
                    + "</b>.  If this was not you, please contact your web team <i>immediately</i> (by replying to this email)."

                    + "<br /><br />"
                    + "Logon to the website at:"
                    + "<b><a href='" + httpPrefix + "://" + Authorisation.ApplicationURL + "'>" + Authorisation.ApplicationURL + "</a></b>"

                    + "<br /><br />"
                    + "Cheers, <br />The " + Authorisation.ApplicationName + " Support Team"

                    + "<br /><br /></p>"
                    ;


            success = MGLSecureEmailer.SendEmail(
                SecureStringWrapper.Decrypt(u.Email),
                SecureStringWrapper.Decrypt(u.FirstName),
                Authorisation.ApplicationName + " - Password updated", messageBody,
                "", null, null, null, null, 0, MGLSecureEmailer.EnableSSL);

            return success;

        }


        //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Make the whole system a bit more user friendly ....
        /// </summary>
        public bool WelcomeEmailUser(MGUser u, DateTime timeStamp, bool useHttps) {
            bool success = false;

            string httpPrefix = (useHttps == true) ? "https" : "http";

            // 25-Nov-2015 - localise the dates
            string prettyLocalDate = "";
            success = LocaliseTime.Localise(lcf, timeStamp, 2, 0, out prettyLocalDate);

            // Send an email
            string messageBody =
                "<p style='font-family: Trebuchet MS;'>"
                    + "Hi " + SecureStringWrapper.Decrypt( u.FirstName ) + ", "
                    + "<br /><br />"
                    + "Welcome to <b>" + Authorisation.ApplicationName
                    + "</b>!  You or an administrator has setup your user credentials on <b>" + prettyLocalDate
                    // DateTimeInformation.PrettyDateTimeFormat(timeStamp, this.timezoneOffset)
                    + "</b>.  If this is a surprise to you, please help us by contacting the web team <i>immediately</i> (by replying to this email)."

                    + "<br /><br />"
                    + "Before using the site, you will need to create your password.  To do this visit the website at "
                    + "<b><a href='" + httpPrefix + "://" + Authorisation.ApplicationURL + "'>" + Authorisation.ApplicationURL + "</a></b> "
                    + " and click on 'login' in the top right corner.  Choose the 'forgot password' link and follow the instructions on screen."

                    + "<br /><br />"
                    + "Cheers, <br />The " + Authorisation.ApplicationName + " Support Team"

                    + "<br /><br /></p>"
                    ;


            //            success = MGLEmailer.SendEmail(u.Email, Authorisation.ApplicationName + " - Welcome", messageBody, "", "", "");
            success = MGLSecureEmailer.SendEmail(
                SecureStringWrapper.Decrypt(u.Email),
                SecureStringWrapper.Decrypt(u.FirstName),
                Authorisation.ApplicationName + " - Welcome", messageBody,
                "", null, null, null, null, 0, MGLSecureEmailer.EnableSSL);

            return success;
        }


    }
}