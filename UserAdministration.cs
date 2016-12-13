using System;
using System.Data;
using System.Configuration;
using MGL.DomainModel;
using System.Collections.Generic;
using System.Threading;
using MGL.Data.DataUtilities;
using System.Security;
using DataNirvana.Database;
using MGL.DomainModel.HumanitarianActivities;

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for Administration
    /// </summary>
    public class UserAdministration {

        #region Statics

        public static readonly string SECURITY_ADMIN_FAILURE_MSG = "A critical failure has occured during security administration. Please contact a system administrator!";

        public static readonly string USER_ADMIN_GET_LOCK_TIMEOUT_MSG = "There was a failure while attempting to access the Users. Please try again ...";

        /// <summary>
        /// A lock object to ensure that only one thread is performing administration on the Users tables at one time.
        /// </summary>
        internal static readonly Object USER_ADMIN_LOCK_OBJ = new Object();

        /// <summary>
        /// A timeout for waiting for sole access to the User tables for administration (in milliseconds).
        /// </summary>
        internal static readonly int USER_ADMIN_LOCK_TIMEOUT = 30000;

        #endregion

        private BaseSecurityOperations _SecurityOperations;
        protected BaseSecurityOperations SecurityOperations {
            get { return _SecurityOperations; }
            set { _SecurityOperations = value; }
        }

        private ConfigurationInfo lcf;

        public ConfigurationInfo Lcf {
            get { return lcf; }
            set { lcf = value; }
        }

        public UserAdministration(ConfigurationInfo lcf) {
            this.Lcf = lcf;
            SecurityOperations = new BaseSecurityOperations(lcf);
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public UserAdministration(int timezoneOffset) {
            SecurityOperations = new BaseSecurityOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);
        }

        public void Finish() {
            if (SecurityOperations != null)
                SecurityOperations.Finish();
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public string GetError() {
            return MGLSessionSecurityInterface.Instance().SecurityError;
        }

        //public bool AddUserUnderDefaultGroups(SecureString username, SecureString email, SecureString password, SecureString jobTitle, SecureString organisation, SecureString telephone) {
        //    MGUser user = new MGUser(username, email, password, jobTitle, organisation, telephone);

        //    return AddUserUnderDefaultGroups(user);
        //}

        /// <summary>
        /// Used by the UserAdminDL to get a list of users DataTable for binding the list
        /// of users in the ModifyUsers control.
        /// </summary>
        /// <param name="orderByString">An optional order by string (should not include the ' Order By ' prefix).</param>
        /// <param name="usernameFilter">An optional username filter string (should include the 'WHERE' prefix)</param>
        /// <returns>A DataTable containing all the users.</returns>
        //public DataTable GetAllUsers(string orderByString, string usernameFilter) {
        //    DataTable dataTable = new DataTable();

        //    DatabaseWrapper db = null;
        //    bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
        //    if (isLockAcquired) {
        //        try {
        //            if (orderByString == null || orderByString == "") {
        //                //Default to order by userid
        //                orderByString = "ID";
        //            }

        //            db = new DatabaseWrapper(Lcf);
        //            db.Connect();

        //            string sql = @"
        //                    SELECT
        //                    ID as UserID,
        //                    UserName,
        //                    'User' as UserType,
        //                    Password,
        //                    StartDate,
        //                    LastLoginDate as LastLogin,
        //                    JobTitle,
        //                    Organisation,
        //                    Telephone,
        //                    Email,
        //                    TotalLogins,
        //                    NumberOfIncorrectLogins
        //                  FROM " + BaseSecurityOperations.tnUsers + " " + usernameFilter + " ORDER BY " + orderByString + ";";

        //            IDataReader myReader = db.RunSqlReader(sql);
        //            dataTable.Load(myReader);
        //        } catch (Exception ex) {
        //            Logger.LogError(8, "Error getting users datatable at " + ex);
        //        } finally {
        //            Monitor.Exit(USER_ADMIN_LOCK_OBJ);
        //            if (db != null)
        //                db.Disconnect();
        //        }
        //    }

        //    return dataTable;
        //}

        //public bool UpdateUser(string userId, SecureString username, SecureString email, SecureString password, SecureString jobTitle, SecureString organisation, int organisationID, SecureString telephone) {
        //    bool isSuccess = false;

        //    bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
        //    if (isLockAcquired) {
        //        try {
        //            MGUser user = new MGUser();

        //            if (!IsPopulated(user, userId, username, email, password, jobTitle, organisation, organisationID, telephone)) {
        //                Logger.LogError(8, "Failed to populate MGUser object. Cannot update user!");
        //                return false;
        //            }

        //            isSuccess = SecurityOperations.UpdateUserDetails(user.ID, user.Username, user.Email, user.JobTitle, user.Organisation, organisationID, user.Telephone);

        //            if (isSuccess && password != null && password.Length > 0) {
        //                isSuccess = SecurityOperations.UpdateUserPassword(user.ID, password, Authorisation.UseMGLRatherThanMySQLPasswordEncryption);
        //                // 12-Jul-15 - should really add an email here - but this is old GEDI code so not doing it for now
        //            }
        //        } catch (Exception ex) {
        //            Logger.LogError(8, "Problem updating user at " + ex);
        //            return false;
        //        } finally {
        //            Monitor.Exit(USER_ADMIN_LOCK_OBJ);
        //        }
        //    }

        //    return isSuccess;
        //}

        ////private bool IsPopulated(MGUser user, string userId,
        ////    SecureString username, SecureString email, SecureString password, SecureString jobTitle, SecureString organisation, int organisationID, SecureString telephone) {

        //    bool isPopulated = false;

        //    if (user == null) {
        //        Logger.LogError(8, "Cannot populate null user object!");
        //        return false;
        //    }

        //    int intUserID = -1;
        //    try {
        //        if (userId == null) {
        //            Logger.LogError(8, "NULL user ID!");
        //            return false;
        //        }

        //        if (!int.TryParse(userId, out intUserID)) {
        //            Logger.LogError(8, "Invalid user ID!");
        //            return false;
        //        }

        //        if (username == null) {
        //            Logger.LogError(8, "NULL username!");
        //            return false;
        //        }

        //        if (email == null) {
        //            Logger.LogWarning("NULL email!");
        //            return false;
        //        }

        //        if (password == null) {
        //            Logger.LogWarning("NULL password!");
        //        }

        //        user.ID = intUserID;
        //        user.Password = password;
        //        user.Username = username;
        //        user.Email = email;
        //        user.JobTitle = jobTitle;
        //        user.Organisation = organisation;
        //        user.OrganisationID = organisationID;
        //        user.Telephone = telephone;

        //        isPopulated = true;
        //    } catch (Exception ex) {
        //        Logger.LogError(8, "Problem populating user at " + ex);
        //        return false;
        //    }

        //    return isPopulated;
        //}

        //public bool DeleteUserAndRemoveFromGroups(int userID) {
        //    bool isSuccess = false;
        //    if (userID < 1 || userID == int.MaxValue) {
        //        Logger.LogError(8, "Cannot delete user with invalid ID!");
        //        return false;
        //    }

        //    BaseSecurityOperations mainDBSecurityOps = null;
        //    BaseSecurityOperations stagingDBSecurityOps = null;
        //    UserAdministration liveDbUserHelper = null;

        //    bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
        //    if (isLockAcquired) {
        //        try {
        //            mainDBSecurityOps = new BaseSecurityOperations(AppSecurityContext.MainDbLcf);
        //            stagingDBSecurityOps = new BaseSecurityOperations(AppSecurityContext.StagingDbLcf);

        //            liveDbUserHelper = new UserAdministration(AppSecurityContext.MainDbLcf);

        //            //---- Step 1: Delete the user from the live database users table.
        //            bool isUserDeletedFromLive = mainDBSecurityOps.DeleteUser(userID);
        //            if (!isUserDeletedFromLive) {
        //                Logger.LogError(8, "Failed to delete user with ID " + userID + " from the live database user table!");
        //                return false;
        //            }

        //            //---- Step 2: Delete the user from the live database groups xref.
        //            bool isUserRemovedFromGroupsLive = mainDBSecurityOps.DeleteUsersGroupXrefs(userID);
        //            if (!isUserRemovedFromGroupsLive) {
        //                Logger.LogWarning("Failed to delete user with ID " + userID + " from the live database group xrefs!");
        //            }

        //            //---- Step 3: Migrate the user table from the Live DB to the staging DB.
        //            bool isMigrated = MigrateUserTable(liveDbUserHelper, AppSecurityContext.MainDbLcf, AppSecurityContext.StagingDbLcf);
        //            if (!isMigrated) {
        //                string msg = SECURITY_ADMIN_FAILURE_MSG;
        //                Logger.LogError(8, msg);
        //                throw new Exception(msg);
        //            }

        //            //---- Step 4: Delete the user from the staging database groups xref.
        //            bool isUserRemovedFromGroupsStaging = stagingDBSecurityOps.DeleteUsersGroupXrefs(userID);
        //            if (!isUserRemovedFromGroupsStaging) {
        //                Logger.LogWarning("Failed to delete user with ID " + userID + " from the staging database group xrefs!");
        //            }

        //            isSuccess = true;
        //        } catch (Exception ex) {
        //            Logger.LogError(8, "Error in UserAdministration.DeleteUser deleting user with ID " + userID + "  at " + ex);
        //            isSuccess = false;
        //        } finally {
        //            Monitor.Exit(USER_ADMIN_LOCK_OBJ);

        //            if (mainDBSecurityOps != null)
        //                mainDBSecurityOps.Finish();
        //            if (stagingDBSecurityOps != null)
        //                stagingDBSecurityOps.Finish();
        //            if (liveDbUserHelper != null)
        //                liveDbUserHelper.Finish();
        //            if (SecurityOperations != null)
        //                SecurityOperations.Finish();
        //        }
        //    } else {   // Couldn't get exclusive lock for user administration.
        //        string msg = USER_ADMIN_GET_LOCK_TIMEOUT_MSG;
        //        Logger.LogError(5, msg);
        //        isSuccess = false;
        //    }

        //    return isSuccess;
        //}

        //public bool AddUserUnderDefaultGroups(MGUser user) {
        //    bool isSuccess = false;

        //    if (user == null) {
        //        Logger.LogError(8, "Cannot add NULL user!");
        //        return false;
        //    }
        //    if (user.Username == null) {
        //        Logger.LogError(8, "Cannot add user with NULL Username under default groups!");
        //        return false;
        //    } else if (user.Username.Length == 0) { // == String.Empty) {
        //        Logger.LogError(8, "Cannot add user with empty Username under default groups!");
        //        return false;
        //    }

        //    BaseSecurityOperations mainDBSecurityOps = null;
        //    GroupAdministration liveDbGroupHelper = null;
        //    GroupAdministration stagingDbGroupHelper = null;
        //    UserAdministration liveDbUserHelper = null;
        //    UserAdministration stagingDbUserHelper = null;

        //    bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
        //    if (isLockAcquired) {
        //        try {
        //            mainDBSecurityOps = new BaseSecurityOperations(AppSecurityContext.MainDbLcf);
        //            liveDbGroupHelper = new GroupAdministration(AppSecurityContext.MainDbLcf);
        //            stagingDbGroupHelper = new GroupAdministration(AppSecurityContext.StagingDbLcf);
        //            liveDbUserHelper = new UserAdministration(AppSecurityContext.MainDbLcf);
        //            stagingDbUserHelper = new UserAdministration(AppSecurityContext.StagingDbLcf);

        //            //---- Step 1: Adding the new user to the live database.
        //            bool isUserAddedToLive = AddNewUser(user, mainDBSecurityOps, liveDbUserHelper);
        //            if (!isUserAddedToLive)
        //                return false;

        //            //---- Step 2: Copying the user table from the Live DB to the staging DB.
        //            bool isMigrated = MigrateUserTable(liveDbUserHelper, AppSecurityContext.MainDbLcf, AppSecurityContext.StagingDbLcf);
        //            if (!isMigrated) {
        //                Logger.LogError(8, "Failed to migrate user table from the source DB  to the dest DB. Removing the user from the source database ...");
        //                bool isSrcDbUserDeleted = liveDbUserHelper.DeleteUser(user.ID);
        //                if (!isSrcDbUserDeleted)
        //                    Logger.LogError(8, "Couldn't delete the user in the source DB!");

        //                string msg = SECURITY_ADMIN_FAILURE_MSG;
        //                Logger.LogError(8, msg);
        //                throw new Exception(msg);
        //            }

        //            //---- Step 3: Adding the new user to the default groups in the live database
        //            Logger.Log("Adding the new user to the default groups in the live database ...");
        //            bool isUsrAddedToDefGrpsLive = AddUserToDefaultGroupsLive(user, liveDbGroupHelper, liveDbUserHelper, stagingDbUserHelper);
        //            if (!isUsrAddedToDefGrpsLive)
        //                return false;

        //            //---- Step 4: Assigning the user to the default groups in the staging DB
        //            bool isUsrAddedToDefGrpsStaging = AddUserToDefaultGroupsStaging(user, liveDbGroupHelper, stagingDbGroupHelper, liveDbUserHelper, stagingDbUserHelper);
        //            if (!isUsrAddedToDefGrpsStaging)
        //                return false;

        //            isSuccess = true;
        //        } catch (Exception ex) {
        //            Logger.LogError(8, "Error in UserAdministration.InsertUser." + ex.Message);
        //            isSuccess = false;
        //            throw ex;
        //        } finally {
        //            Monitor.Exit(USER_ADMIN_LOCK_OBJ);

        //            if (mainDBSecurityOps != null)
        //                mainDBSecurityOps.Finish();
        //            if (liveDbUserHelper != null)
        //                liveDbUserHelper.Finish();
        //            if (stagingDbUserHelper != null)
        //                stagingDbUserHelper.Finish();
        //            if (SecurityOperations != null)
        //                SecurityOperations.Finish();
        //        }
        //    } else {   // Couldn't get exclusive lock for user administration.
        //        string msg = USER_ADMIN_GET_LOCK_TIMEOUT_MSG;
        //        Logger.LogError(5, msg);
        //        isSuccess = false;
        //        throw new Exception(msg);
        //    }

        //    return isSuccess;
        //}

        //private bool AddUserToDefaultGroupsStaging(MGUser user, GroupAdministration liveDbGroupHelper, GroupAdministration stagingDbGroupHelper, UserAdministration liveDbUserHelper, UserAdministration stagingDbUserHelper) {
        //    bool isSuccess = false;

        //    try {
        //        Logger.Log("Assigning the user to the default groups in the staging DB ...");
        //        isSuccess = stagingDbGroupHelper.AssignUserToDefaultGroups(user.ID);
        //        if (!isSuccess) {
        //            Logger.LogError(8, "Failed to assign user (" + user.Username + ") to default groups in staging database!");

        //            Logger.Log("Deleting user from live database!");
        //            bool isLiveUserDeleted = liveDbUserHelper.DeleteUser(user.ID);
        //            if (!isLiveUserDeleted)
        //                Logger.LogError(8, "Couldn't delete the live user!");

        //            Logger.Log("Removing user from all groups in the live database ...");
        //            bool isUserUnassigned = liveDbGroupHelper.UnassignAllGroupsFromUser(user.ID);
        //            if (!isLiveUserDeleted)
        //                Logger.LogError(8, "Couldn't remove the group associations for the live user!");

        //            Logger.Log("Deleting user from staging database!");
        //            bool isStagingUserDeleted = stagingDbUserHelper.DeleteUser(user.ID);
        //            if (!isStagingUserDeleted)
        //                Logger.LogError(8, "Couldn't delete the user from the staging database!");

        //            isSuccess = false;
        //        } else
        //            Logger.Log("Finished assigning the User in the staging DB to the staging DB default groups ...");
        //    } catch (Exception ex) {
        //        Logger.LogError(8, ex.ToString());
        //        isSuccess = false;
        //    }

        //    return isSuccess;
        //}

        //private bool AddUserToDefaultGroupsLive(MGUser user, GroupAdministration liveDbGroupHelper, UserAdministration liveDbUserHelper, UserAdministration stagingDbUserHelper) {
        //    bool isSuccess = false;

        //    try {
        //        isSuccess = liveDbGroupHelper.AssignUserToDefaultGroups(user.ID);
        //        if (!isSuccess) {
        //            Logger.LogError(8, "Failed to assign user (" + user.Username + ") to default groups in live database! Abandoning adding user under default groups!");

        //            Logger.Log("Deleting user from live database!");
        //            bool isLiveUserDeleted = liveDbUserHelper.DeleteUser(user.ID);
        //            if (!isLiveUserDeleted)
        //                Logger.LogError(8, "Couldn't delete the live user!");

        //            Logger.Log("Deleting user from staging database!");
        //            bool isStagingUserDeleted = stagingDbUserHelper.DeleteUser(user.ID);
        //            if (!isStagingUserDeleted)
        //                Logger.LogError(8, "Couldn't delete the user from the staging database!");

        //            isSuccess = false;
        //        } else
        //            Logger.Log("Finished adding the new user to the default groups in the live database.");
        //    } catch (Exception ex) {
        //        Logger.LogError(8, ex.ToString());
        //        return false;
        //    }

        //    return isSuccess;
        //}

        //private bool MigrateUserTable(UserAdministration userDbHelper, ConfigurationInfo srcLcf, ConfigurationInfo destLcf) {
        //    bool isMigrated = false;

        //    //try
        //    //{
        //    //    string srcDbName = srcLcf.DbConInfo.NAME;
        //    //    string destDbName = destLcf.DbConInfo.NAME;

        //    //    Logger.Log("Copying the user table from the source DB (" + srcDbName + ") to the dest DB (" + destDbName + ") ...");

        //    //    isMigrated = userDbHelper.MigrateTable(BaseSecurityOperations.tnUsers, srcLcf, destLcf);
        //    //    if (!isMigrated)
        //    //    {
        //    //        string msg = SECURITY_ADMIN_FAILURE_MSG;
        //    //        Logger.LogError(msg);
        //    //    }
        //    //    else
        //    //        Logger.Log("Finished copying the User table from the source DB (" + srcDbName + ") to the dest DB (" + destDbName + ").");
        //    //}
        //    //catch (Exception ex)
        //    //{
        //    //    Logger.LogError("Problem migrating user table at " + ex);
        //    //    isMigrated = false;
        //    //    throw ex;
        //    //}

        //    return isMigrated;
        //}

        //private bool AddNewUser(MGUser user, BaseSecurityOperations dbSecurityOps, UserAdministration userDbHelper) {
        //    bool isAdded = false;

        //    MGUser addedUser = null;

        //    try {
        //        Logger.Log("Adding the new user to the live database ...");
        //        bool isInsertedToMain = dbSecurityOps.InsertUser(user);
        //        if (!isInsertedToMain) {
        //            Logger.LogError(8, "Failed to insert user (" + user.Username + ") into main database! Abandoning adding user under default groups!");
        //            return false;
        //        } else
        //            Logger.Log("Finished Adding the new user to the live database.");

        //        Logger.Log("Getting the new user from the live database ...");
        //        addedUser = userDbHelper.GetUser(user.Username);
        //        if (user == null) {
        //            Logger.LogError(8, "Failed to retrieve new user from main live database!");
        //            return false;
        //        } else if (addedUser.ID < 1 || addedUser.ID == int.MaxValue) {
        //            Logger.LogError(8, "Failed to retrieve new user with valid ID from main live database!");
        //            return false;
        //        } else
        //            Logger.Log("Finished successfully getting the new user from the live database.");

        //        user.ID = addedUser.ID;
        //        isAdded = true;
        //    } catch (Exception ex) {
        //        Logger.LogError(8, "Error adding AddNewUserToLiveDb in " + ex.StackTrace);
        //        return false;
        //    }

        //    return isAdded;
        //}

        //private bool MigrateTable(
        //    string tablename,
        //    ConfigurationInfo srcDbConfig,
        //    ConfigurationInfo destDbConfig)
        //{
        //    bool isMigrated = false;

        //    if (tablename == null || tablename == String.Empty)
        //    {
        //        Logger.LogError("Cannot migrate tablename with NULL or empty name. Abandoning migrating table ...");
        //        return false;
        //    }

        //    string srcDbName = srcDbConfig.__DefaultDatabaseConnectionInformation.NAME;
        //    string destDbName = srcDbConfig.__DefaultDatabaseConnectionInformation.NAME;
        //    DatabaseInformation srcDb = null;
        //    DatabaseInformation destDb = null;
        //    DBMigrator dbMigrator = null;

        //    try
        //    {
        //        srcDb = new DatabaseInformation(false, srcDbConfig);
        //        destDb = new DatabaseInformation(false, destDbConfig);

        //        dbMigrator = new DBMigrator(srcDbConfig);

        //        isMigrated = dbMigrator.Migrate(tablename, srcDb, destDb, true);
        //        if (isMigrated)
        //            Logger.Log("Finishing migrating table (" + tablename + ") from src DB (" + srcDbName + ") to dest DB (" + destDbName + ").");
        //        else
        //            Logger.LogError("Failed to migrate table (" + tablename + ") from src DB (" + srcDbName + ") to dest DB (" + destDbName + ")!");
        //    }
        //    catch (Exception ex)
        //    {
        //        Logger.LogError("Failed to migrate table (" + tablename + ") from src DB (" + srcDbName + ") to dest DB (" + destDbName + ") at " + ex);
        //        return false;
        //    }
        //    finally
        //    {
        //        if (srcDb != null)
        //            srcDb.Disconnect();

        //        if (destDb != null)
        //            destDb.Disconnect();
        //    }

        //    return isMigrated;
        //}

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// This ONLY updates the user to group xref.
        /// (note that this requires that the application
        ///  variable that contains the user to group xref
        ///  dictionary is updated also).
        /// If a full user security model is implemented (i.e.
        ///  filtering content AND functionality) the necessary
        ///  tables and xref variables must also be updated/refreshed
        ///  here.
        ///
        /// </summary>
        /// <param name="Username"></param>
        /// <param name="Email"></param>
        /// <param name="Password"></param>
        /// <param name="JobTitle"></param>
        /// <param name="Organisation"></param>
        /// <param name="Telephone"></param>
        /// <param name="userGroup"></param>
        /// <returns></returns>
        //public bool AddUser(
        //    SecureString Username, SecureString Email, SecureString Password, SecureString JobTitle, SecureString OrganisationAcronym,
        //    SecureString Telephone, MGGroupType userGroup) {

        //    bool result = false;

        //    try {
        //        int orgID = 0;
        //        foreach (Organisation org in KeyInfo.AllOrganisations.Values) {
        //            if (SecureStringWrapper.AreEqual(OrganisationAcronym, SecureStringWrapper.Encrypt(org.OrganisationAcronym), false) == true) {
        //                orgID = org.ID;
        //                break;
        //            }
        //        }

        //        result = SecurityOperations.InsertUser(Username, Email, Password, JobTitle, Organisation, Telephone);

        //        if (result) {
        //            DateTime pWordChangeTimeStamp = DateTime.Now;

        //            // 13-Jul-2015 - lets email the user to confirm that their password has changed!
        //            // No this is old - unused code, so lets kill this for now ... and just update the password change date

        //            SecurityOperations.UpdatePasswordChangeDate(Username, pWordChangeTimeStamp);
        //        }

        //        if (result) {
        //            //need to add the user to the user_groups xref's
        //            result = SecurityOperations.UpdateUserToGroupXref(Username, userGroup);

        //            //need to update the applications user to group to  xref's
        //            if (result) {
        //                UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

        //                Dictionary<int, List<int>> userGroupDict = userOps.UserGroupDictionary();
        //                userOps.Finish();

        //                MGLApplicationSecurityInterface.Instance().UserGroupXref = userGroupDict;
        //            }
        //        }
        //    } catch (Exception ex) {
        //        Logger.LogError(8, "Error in UserAdministration.AddUser." + ex.Message);
        //    } finally {
        //        SecurityOperations.Finish();
        //    }

        //    return result;
        //}


        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool EditUser() {

            return false;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool EmailAlreadyExists(SecureString emailAddress) {
            bool result = false;

            try {
                result = SecurityOperations.EmailAlreadyExists(emailAddress);
            } catch (Exception ex) {
                Logger.LogError(8, "Problem checking if email exists at " + ex);
                return true; // return true, in case they are trying to add this email.
            } finally {
                SecurityOperations.Finish();
            }

            return result;
        }
        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UserNameAlreadyExists(SecureString username) {
            bool result = false;

            try {
                result = SecurityOperations.UserNameAlreadyExists(username);
            } catch (Exception ex) {
                Logger.LogError(8, "Problem checking if username exists at " + ex);
                return true; // return true, in case they are trying to add this username.
            } finally {
                SecurityOperations.Finish();
            }

            return result;
        }

        //--------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool DeleteUser(int userID) {

            bool result = false;
            UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

            try {
                result = userOps.DeleteUser(userID);
                result = result && userOps.DeleteUsersGroupXrefs(userID);
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.DeleteUser." + ex.Message);
            } finally {
                userOps.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<MGUser> GetUsers(string filterByType, string filterByValue, string sortColumn, List<string> PreviousSortColumnNames, System.Web.UI.WebControls.SortDirection sortDirection) {
            List<MGUser> result = new List<MGUser>();

            UserOperations userOps = null;
            bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
            if (isLockAcquired) {
                try {
                    userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

                    result = userOps.GetAllUsers(filterByType, filterByValue, sortColumn, PreviousSortColumnNames, sortDirection);
                } catch (Exception ex) {
                    Logger.LogError(8, "Error in UserAdministration.GetUsers." + ex.Message);
                } finally {
                    Monitor.Exit(USER_ADMIN_LOCK_OBJ);
                    if (userOps != null)
                        userOps.Finish();
                }
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public DataTable GetUserDetailSQL(int userID) {
            DataTable dataTable = new DataTable();

            bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
            if (isLockAcquired) {
                DatabaseWrapper db = null;

                try {
                    db = new DatabaseWrapper(AppSecurityContext.MainDbLcf);
                    db.Connect();

                    string sql = @"SELECT
                    ID as UserID,
                    UserName,
                    'User' as UserType,
                    Password,
                    LastLoginDate as LastLogin,
                    JobTitle,
                    Organisation,
                    Telephone,
                    Email,
                    NumberOfIncorrectLogins
                    FROM " + BaseSecurityOperations.tnUsers + " where ID =" + userID;

                    IDataReader myReader = db.RunSqlReader(sql);
                    dataTable.Load(myReader);
                } catch (Exception ex) {
                    Logger.LogError(8, "Problem getting user detail DataTable at " + ex);
                    return dataTable;
                } finally {
                    Monitor.Exit(USER_ADMIN_LOCK_OBJ);
                    if (db != null)
                        db.Disconnect();
                }
            } else {
                Logger.LogError(8, "Failed to get exclusive lock in GetUserDetailSQL to read the Users table!");
                return dataTable;
            }

            return dataTable;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<MGUser> GetUsers(List<string> fieldsToSearch, string valueToSearch, string sortColumnName, System.Web.UI.WebControls.SortDirection sortDirection) {
            List<MGUser> result = new List<MGUser>();

            UserOperations userOps = null;

            bool isLockAcquired = Monitor.TryEnter(USER_ADMIN_LOCK_OBJ, USER_ADMIN_LOCK_TIMEOUT);
            if (isLockAcquired) {
                try {
                    userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

                    result = userOps.GetAllUsers(fieldsToSearch, valueToSearch, sortColumnName, sortDirection);
                } catch (Exception ex) {
                    Logger.LogError(8, "Error in UserAdministration.GetUsers (Without PreviousSortColumnNames)." + ex.Message);
                } finally {
                    Monitor.Exit(USER_ADMIN_LOCK_OBJ);
                    if (userOps != null)
                        userOps.Finish();
                }
            } else {
                Logger.LogError(8, "Failed to get exclusive lock in GetUsers to read the Users table!");
                return result;
            }

            return result;
        }


        ////-------------------------------------------------------------------------------------------------------------------------------------------------------------
        ///// <summary>
        ///// If deleteExisting groups is true the entered group type will overwrite
        ///// any existing groups assigned to this user. (This is require where
        ///// a user can only belong to one group)
        ///// </summary>
        ///// <param name="updatedUser"></param>
        ///// <param name="groupType"></param>
        ///// <param name="deleteExistingGroups"></param>
        ///// <returns></returns>
        //public bool EditUserPassword(int userID, SecureString Password, MGGroupType groupType, bool p) {
        //    bool result = false;

        //    try {
        //        result = SecurityOperations.UpdateUserPassword(userID, Password, Authorisation.UseMGLRatherThanMySQLPasswordEncryption);

        //        if (result) {
        //            DateTime pWordChangeTimeStamp = DateTime.Now;

        //            SecurityOperations.UpdatePasswordChangeDate(userID, pWordChangeTimeStamp);
        //            // 13-Jul-2015 - lets email the user to confirm that their password has changed!
        //            MGUser u = null;
        //            Authorisation.GetUser(userID, out u);
        //            SecurityOperations.PasswordChangedEmailUser(u, pWordChangeTimeStamp);

        //        }
        //    } catch (Exception ex) {
        //        Logger.Log("Error in UserAdministration.AddUser." + ex.Message);
        //    } finally {
        //        SecurityOperations.Finish();
        //    }

        //    return result;
        //}


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// If deleteExisting groups is true the entered group type will overwrite
        /// any existing groups assigned to this user. (This is require where
        /// a user can only belong to one group)
        /// </summary>
        /// <param name="updatedUser"></param>
        /// <param name="groupType"></param>
        /// <param name="deleteExistingGroups"></param>
        /// <returns></returns>
        public bool EditUserDetails(MGUser updatedUser, MGGroupType groupType, bool p) {
            bool result = false;

            try {
                result = SecurityOperations.UpdateUserDetails(updatedUser.ID, updatedUser.Username, updatedUser.Email, updatedUser.JobTitle, 
                    updatedUser.Organisation, updatedUser.OrganisationID, updatedUser.Telephone);

                //need to add the user to the user_groups xref's
                result = result && SecurityOperations.DeleteUsersGroupXrefs(updatedUser.ID);
                result = result && SecurityOperations.UpdateUserToGroupXref(updatedUser.Username, groupType);

                //need to update the applications user to group to  xref's
                if (result) {
                    UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

                    Dictionary<int, List<int>> userGroupDict = userOps.UserGroupDictionary();
                    userOps.Finish();

                    MGLApplicationSecurityInterface.Instance().UserGroupXref = userGroupDict;
                }
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.AddUser." + ex.Message);
            } finally {
                SecurityOperations.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUser(int selectedUserID) {
            MGUser result = new MGUser();

            UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

            try {
                result = userOps.GetUser(selectedUserID);
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.GetUser by id." + ex.Message);
            } finally {
                userOps.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUser(SecureString userName) {
            MGUser result = new MGUser();

            UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

            try {
                result = userOps.GetUser(userName);
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.GetUser by id." + ex.Message);
            } finally {
                userOps.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUserByUsername(SecureString userName) {
            MGUser result = new MGUser();

            UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

            try {
                result = userOps.GetUserByUsername(userName);
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.GetUserByUsername at " + ex);
            } finally {
                userOps.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGUser GetUserByEmail(SecureString email) {
            MGUser result = new MGUser();

            UserOperations userOps = new UserOperations(MGLApplicationSecurityInterface.Instance().DatabaseConfig);

            try {
                result = userOps.GetUserByEmail(email);
            } catch (Exception ex) {
                Logger.LogError(8, "Error in UserAdministration.GetUserByEmail b at " + ex);
            } finally {
                userOps.Finish();
            }

            return result;
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static string GetUnlockUserSql(string userID) {
            if (userID == null) {
                return null;
            }

            int intUserID = -1;
            if (!int.TryParse(userID, out intUserID)) {
                return null;
            }

            string sql =
                @"UPDATE " + BaseSecurityOperations.tnUsers + @"
                SET numberofincorrectlogins=0
                WHERE ID = " + userID + ";";

            return sql;
        }
    }



}