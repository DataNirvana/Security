using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Collections.Generic;
using MGL.Security;
using System.Text;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using DataNirvana.Database;

/// <summary>
/// A class for providing access to the ASP.NET Web Application-level based security context which
/// is based on Users->UserGroup->Content relationships.
/// </summary>

namespace MGL.Security
{

    public class AppSecurityContext
    {

        #region Statics

        public static ConfigurationInfo MainDbLcf
        {
            get
            {
                // these are read from the web config entries.
                return MGLApplicationSecurityInterface.Instance().DatabaseConfig;
            }
        }

        public static ConfigurationInfo StagingDbLcf
        {
            get
            {
                // these are read from the web config (staging) entries.
                return MGLApplicationSecurityInterface.Instance().DatabaseConfig;
            }
        }

        #endregion

        #region Properties

        private ConfigurationInfo lcf = null;
        /// <summary>
        /// The configuration file for the app security context.
        /// Specifies which DB the application security tables are in.
        /// </summary>
        public ConfigurationInfo Lcf
        {
            get
            {
                return lcf;
            }
            set
            {
                lcf = value;
            }
        }

        public Dictionary<int, GroupPermissions> AllGroupPermissions
        {
            get
            {
                if (Lcf.DbConInfo.NAME.Equals(
                        AppSecurityContext.StagingDbLcf.DbConInfo.NAME,
                        StringComparison.CurrentCultureIgnoreCase)
                    )
                {
                    return GetAllGroupPermissions();
                }

                Dictionary<int, GroupPermissions> allGroupPermissions = null;
                if (HttpContext.Current.Application[ALL_GROUP_APP_KEY] == null)
                {
                    allGroupPermissions = GetAllGroupPermissions();
                    HttpContext.Current.Application[ALL_GROUP_APP_KEY] = allGroupPermissions;
                }
                else
                {
                    allGroupPermissions = HttpContext.Current.Application[ALL_GROUP_APP_KEY] as Dictionary<int, GroupPermissions>;
                }

                if (allGroupPermissions == null || allGroupPermissions.Count == 0)
                {
                    Logger.LogError(5, "Failed to populate the AllGroupPermissions property!");
                }

                return allGroupPermissions;

            }
            set
            {
                HttpContext.Current.Application[ALL_GROUP_APP_KEY] = value;
            }
        }

        public Dictionary<int, int> ZoomLevelIdGeoTypeIdLookup
        {
            get
            {
                Dictionary<int, int> zoomLevelIdGeoTypeIdLookup = null;
                if (HttpContext.Current.Application[ZLI_GEO_ID_LOOKUP_APP_KEY] == null)
                {
                    zoomLevelIdGeoTypeIdLookup = GetZoomLevelIdGeoTypeIdLookup();
                    HttpContext.Current.Application[ZLI_GEO_ID_LOOKUP_APP_KEY] = zoomLevelIdGeoTypeIdLookup;
                }
                else
                {
                    zoomLevelIdGeoTypeIdLookup = HttpContext.Current.Application[ZLI_GEO_ID_LOOKUP_APP_KEY] as Dictionary<int, int>;
                }

                if (zoomLevelIdGeoTypeIdLookup == null || zoomLevelIdGeoTypeIdLookup.Count == 0)
                {
                    string msg = "Failed to populate the ZoomLevelIdGeoTypeIdLookup property!";
                    Logger.LogError(5, msg);
                    Logger.LogError(5, msg);
                }

                return zoomLevelIdGeoTypeIdLookup;

            }
            set
            {
                HttpContext.Current.Application[ZLI_GEO_ID_LOOKUP_APP_KEY] = value;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new AppSecurityContext.
        /// </summary>
        public AppSecurityContext(ConfigurationInfo lcf)
        {
            Lcf = lcf;
        }

        #endregion

        #region Public Methods

        public GroupPermissions GetUnassignedAnyGroupPermissions()
        {
            GroupPermissions groupPermissions = null;
            GroupOperations groupOps = null;
            try
            {
                groupOps = new GroupOperations(Lcf);

                Logger.Log("Getting group security permission key value pairs ...");
                List<MGSecurityTag> groupContentList = groupOps.GetUnassignedAnyGroupContentDictionary();
                if (groupContentList == null )
                {
                    Logger.LogError(5, "Got NULL or empty list for group permissions that aren't assigned to to ANY group!");
                    return null;
                }

                Logger.Log("Finished getting group security permission key value pairs.");

                groupPermissions = GetGroupPermissions(MGGroup.NO_GROUP, groupContentList);
                if (groupPermissions == null)
                {
                    Logger.LogError(5, "Failed to get group permissions that aren't assigned to ANY group!");
                    return null;
                }
                Logger.Log("Finished getting group permissions that aren't assigned to ANY group.");
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all group permissions at " + ex.StackTrace);
                groupPermissions = null;
            }
            finally
            {
                if (groupOps != null)
                    groupOps.Finish();
            }
            return groupPermissions;
        }

        public GroupPermissions GetGroupPermissions(MGGroup group)
        {
            return GetGroupPermissions(group, GroupAdministration.AssociationTypes.Assign);
        }

        public GroupPermissions GetGroupPermissions(MGGroup group, GroupAdministration.AssociationTypes associationType)
        {
            if (group == null)
            {
                Logger.LogError(5, "NULL  group found can not find permissions.");
                return null;
            }
            GroupPermissions groupPermissions = null;
            GroupOperations groupOps = null;

            Logger.Log("Getting group permissions for group with ID " + group.ID + " and name " + group.Name + "...");
            try
            {
                Logger.Log("Getting group security permission key value pairs ...");

                // Extract the Application Level list of groups, along with the relevant cross references to Users and the content etc ...
                groupOps = new GroupOperations(Lcf);

                Logger.Log("Start getting groups->content lookup...");
                List<MGSecurityTag> groupContentList = groupOps.GetGroupContentDictionary(group.ID, associationType);
                if (groupContentList == null)
                {
                    Logger.LogError(5, "Got NULL list for group with name " + group.Name + " and ID " + group.ID + " groups->content lookup, abandoning getting group permissions!");
                    return null;
                }

                Logger.Log("Start getting groups->display lookup...");
                List<MGSecurityTag> groupDisplayList = groupOps.GetGroupDisplayDictionary(group.ID, associationType);
                if (groupDisplayList == null)
                {
                    Logger.LogError(5, "Got NULL list for group with name " + group.Name + " and ID " + group.ID + " groups->display lookup, abandoning getting group permissions!");
                    return null;
                }

                Logger.Log("Start getting groups->functionality lookup...");
                List<MGSecurityTag> groupFunctionalityList = groupOps.GetGroupFunctionalityDictionary(group.ID, associationType);
                if (groupFunctionalityList == null)
                {
                    Logger.LogError(5, "Got NULL list for group with name " + group.Name + " and ID " + group.ID + " groups->functionality lookup, abandoning getting group permissions!");
                    return null;
                }

                Logger.Log("Finished getting group security permission key value pairs.");

                groupPermissions = GetGroupPermissions(group, groupContentList, groupDisplayList, groupFunctionalityList);
                if (groupPermissions == null)
                {
                    Logger.LogError(5, "Failed to get group permissions for group with name " + group.Name + " and ID " + group.ID + "!");
                    return null;
                }
                Logger.Log("Finished getting group permissions for group with name " + group.Name + " and ID " + group.ID + ".");
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all group permissions at " + ex.StackTrace);
                groupPermissions = null;
            }
            finally
            {
                if (groupOps != null)
                    groupOps.Finish();
            }
            return groupPermissions;
        }

        public Dictionary<int, GroupPermissions> GetAllGroupPermissions()
        {
            Logger.Log("Getting all group permissions ...");

            Dictionary<int, GroupPermissions> allGroupPermissions = null;

            GroupOperations groupOps = null;
            try
            {
                // Extract the Application Level list of groups, along with the relevant cross references to Users and the content etc ...
                groupOps = new GroupOperations(Lcf);

                Logger.Log("Getting all groups ...");
                List<MGGroup> allGroups = groupOps.GetAllGroups();
                if (allGroups == null)
                {
                    Logger.LogError(5, "Got NULL list for all groups, abandoning getting group permissions!");
                    return null;
                }
                if (allGroups.Count == 0)
                {
                    Logger.LogWarning("Got empty list for all groups, returning empty group permissions ...");
                    return new Dictionary<int, GroupPermissions>();
                }

                Logger.Log("Got all " + allGroups.Count + " groups.");

                Logger.Log("Getting group security permission key value pairs ...");

                Dictionary<int, List<MGSecurityTag>> groupContentDict = groupOps.GroupContentDictionary();
                if (groupContentDict == null)
                {
                    Logger.LogError(5, "Got NULL list for groups->content lookup, abandoning getting group permissions!");
                    return null;
                }

                Dictionary<int, List<MGSecurityTag>> groupDisplayDict = groupOps.GroupDisplayDictionary();
                if (groupDisplayDict == null)
                {
                    Logger.LogError(5, "Got NULL list for groups->display lookup, abandoning getting group permissions!");
                    return null;
                }

                Dictionary<int, List<MGSecurityTag>> groupFunctionalityDict = groupOps.GroupFunctionalityDictionary();
                if (groupFunctionalityDict == null)
                {
                    Logger.LogError(5, "Got NULL list for groups->functionality lookup, abandoning getting group permissions!");
                    return null;
                }

                Logger.Log("Finished getting group security permission key value pairs.");

                allGroupPermissions = GetAllGroupPermissions(allGroups, groupContentDict, groupDisplayDict, groupFunctionalityDict);

                Logger.Log("Finished getting all group permissions.");
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all group permissions at " + ex.StackTrace);
                allGroupPermissions = null;
            }
            finally
            {
                if (groupOps != null)
                    groupOps.Finish();
            }

            return allGroupPermissions;
        }

        public Dictionary<int, int> GetZoomLevelIdGeoTypeIdLookup()
        {
            Dictionary<int, int> zoomLevelIdGeoTypeIdLookup = null;

            DatabaseWrapper db = null;
            IDataReader reader = null;
            try
            {
                Logger.Log("Getting zoom level ID -> geogTypeID lookup ...");

                db = new DatabaseWrapper(Lcf);
                db.Connect();

                StringBuilder builder = new StringBuilder();
                builder.Append("SELECT svgTableSIZL_ID, dlg_ID FROM dl_geographies GROUP BY svgTableSIZL_ID;");
                string sql = builder.ToString();
                reader = db.RunSqlReader(sql);

                if (reader == null)
                {
                    Logger.LogError(5, "Error getting reader using SQL " + sql);
                }

                string svgTableSIZL_ID = null;
                string dlg_ID = null;
                int intSvgTableSIZL_ID = -1;
                int intDlg_ID = -1;

                while (reader.Read())
                {
                    svgTableSIZL_ID = null;
                    dlg_ID = null;
                    intSvgTableSIZL_ID = -1;
                    intDlg_ID = -1;

                    if (zoomLevelIdGeoTypeIdLookup == null)
                        zoomLevelIdGeoTypeIdLookup = new Dictionary<int, int>();

                    if (reader["svgTableSIZL_ID"] != System.DBNull.Value)
                    {
                        svgTableSIZL_ID = reader["svgTableSIZL_ID"].ToString();
                        if(!int.TryParse(svgTableSIZL_ID, out intSvgTableSIZL_ID))
                        {
                            Logger.LogError(5, "Non-integer svgTableSIZL_ID read from dl_geographies!");
                            continue;
                        }
                    }
                    else
                    {
                        Logger.LogError(5, "NULL svgTableSIZL_ID read from dl_geographies!");
                        continue;
                    }

                    if (reader["dlg_ID"] != System.DBNull.Value)
                    {
                        dlg_ID = reader["dlg_ID"].ToString();
                        if (!int.TryParse(dlg_ID, out intDlg_ID))
                        {
                            Logger.LogError(5, "Non-integer dlg_ID read from dl_geographies!");
                            continue;
                        }
                    }
                    else
                    {
                        Logger.LogError(5, "NULL dlg_ID read from dl_geographies!");
                        continue;
                    }

                    if (!zoomLevelIdGeoTypeIdLookup.ContainsKey(intSvgTableSIZL_ID))
                    {
                        zoomLevelIdGeoTypeIdLookup.Add(intSvgTableSIZL_ID, intDlg_ID);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Problem in GetZoomLevelIdGeoTypeIdLookup at " + ex);
                return null;
            }
            finally
            {
                if (reader != null && !reader.IsClosed)
                {
                    reader.Close();
                }

                if (db != null)
                {
                    db.Disconnect();
                }
            }

            if (zoomLevelIdGeoTypeIdLookup.Count == 0)
            {
                Logger.LogError(5, "zoomLevelIdGeoTypeIdLookup was populated with zero records!");
            }

            return zoomLevelIdGeoTypeIdLookup;
        }

        private Dictionary<int, GroupPermissions> GetAllGroupPermissions(List<MGGroup> allGroups,
            Dictionary<int, List<MGSecurityTag>> groupContentDict,
            Dictionary<int, List<MGSecurityTag>> groupDisplayDict,
            Dictionary<int, List<MGSecurityTag>> groupFunctionalityDict)
        {
            Dictionary<int, GroupPermissions> allGroupPermissions = new Dictionary<int, GroupPermissions>(allGroups.Count);
            try
            {
                GroupPermissions groupPerms = null;
                List<MGSecurityTag> groupContentSecKeyValPairs = null;
                List<MGSecurityTag> groupDisplaySecKeyValPairs = null;
                List<MGSecurityTag> groupFunctionSecKeyValPairs = null;

                foreach (MGGroup group in allGroups)
                {
                    if (group == null)
                    {
                        Logger.LogError(5, "NULL MGGroup detected, skipping getting group permissions for this group ...");
                        continue;
                    }
                    else if (group.ID < 1)
                    {
                        Logger.LogError(5, "Invalid MGGroup.ID detected, skipping getting group permissions for this group ...");
                        continue;
                    }

                    groupContentSecKeyValPairs = null;
                    groupDisplaySecKeyValPairs = null;
                    groupFunctionSecKeyValPairs = null;

                    if (groupContentDict.ContainsKey(group.ID))
                    {
                        groupContentSecKeyValPairs = groupContentDict[group.ID];
                    }

                    if (groupDisplayDict.ContainsKey(group.ID))
                    {
                        groupDisplaySecKeyValPairs = groupDisplayDict[group.ID];
                    }

                    if (groupFunctionalityDict.ContainsKey(group.ID))
                    {
                        groupFunctionSecKeyValPairs = groupFunctionalityDict[group.ID];
                    }

                    groupPerms = GetGroupPermissions(group, groupContentSecKeyValPairs, groupDisplaySecKeyValPairs, groupFunctionSecKeyValPairs);
                    if (groupPerms == null)
                    {
                        Logger.LogError(5, "Failed to get GroupPermissions for group.ID=" + group.ID);
                        continue;
                    }
                    if (!allGroupPermissions.ContainsKey(group.ID))
                        allGroupPermissions.Add(group.ID, groupPerms);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting all group permissions at " + ex.StackTrace);
                allGroupPermissions = null;
            }
            return allGroupPermissions;
        }


        public GroupPermissions GetGroupPermissions(MGGroup group, List<MGSecurityTag> groupContentSecKeyValPairs)
        {
            return GetGroupPermissions(group, groupContentSecKeyValPairs, null, null);
        }

        public GroupPermissions GetGroupPermissions(MGGroup group,
            List<MGSecurityTag> groupContentSecKeyValPairs,
            List<MGSecurityTag> groupDisplaySecKeyValPairs,
            List<MGSecurityTag> groupFunctionSecKeyValPairs)
        {
            GroupPermissions groupPerms = null;

            try
            {
                groupPerms = new GroupPermissions();
                groupPerms.GroupID = group.ID;

                if (groupContentSecKeyValPairs != null)
                {
                    groupPerms.GroupContentPermissions =
                       groupPerms.GetGroupContentPermissions(groupContentSecKeyValPairs);
                }

                if (groupDisplaySecKeyValPairs != null)
                {
                    groupPerms.GroupDisplayPermissions =
                       groupPerms.GetGroupDisplayPermissions(groupDisplaySecKeyValPairs);
                }

                if (groupFunctionSecKeyValPairs != null)
                {
                    groupPerms.GroupFunctionPermissions =
                        groupPerms.GetGroupFunctionPermissions(groupFunctionSecKeyValPairs);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting group permissions for group with ID=" + group.ID + " at " + ex.StackTrace);
                groupPerms = null;
            }
            return groupPerms;
        }


        //public bool MigrateSecurityModel()
        //{
        //    Logger.Log("Attempting to migrate the security model ");

        //    bool isMigrated = false;
        //    string dbName = Lcf.DbConInfo.NAME;
        //    DatabaseInformation db = null;
        //    try
        //    {
        //        db = new DatabaseInformation(Lcf);
        //        db.Connect();

        //        if (!db.TableExists(LEGACY_SECURITY_TABLENAME))
        //        {
        //            Logger.LogWarning("Abandoning migrating security model as legacy table " + LEGACY_SECURITY_TABLENAME + " does not exist to migrate in database " + dbName);
        //            return false;
        //        }

        //        string[] requiredTables = new string[] {
        //            BaseSecurityOperations.tnUsers,
        //            BaseSecurityOperations.tnGroups,
        //            BaseSecurityOperations.tnContent,
        //            BaseSecurityOperations.tnDisplay,
        //            BaseSecurityOperations.tnFunctionality,
        //            BaseSecurityOperations.tnXrefGroupsUsers,
        //            BaseSecurityOperations.tnXrefGroupsContent,
        //            BaseSecurityOperations.tnXrefGroupsFunctionality,
        //            BaseSecurityOperations.tnXrefGroupsDisplay};

        //        for (int i = 0; i < requiredTables.Length; i++)
        //        {
        //            if (!db.TableExists(requiredTables[i]))
        //            {
        //                Logger.LogWarning("Abandoning migrating security model as new security model table " + requiredTables[i] + " does not exist in database " + dbName + ". Please ensure that this table exists and is empty!");
        //                return false;
        //            }
        //        }

        //        string[] requiredEmptyTables = new string[] {
        //            BaseSecurityOperations.tnUsers,
        //            BaseSecurityOperations.tnXrefGroupsContent,
        //            BaseSecurityOperations.tnXrefGroupsUsers};

        //        for (int i = 0; i < requiredEmptyTables.Length; i++)
        //        {
        //            if (db.GetCount(requiredEmptyTables[i]) > 0)
        //            {
        //                Logger.LogWarning("Abandoning migrating security model as new security model table " + requiredTables[i] + " is not empty in database " + dbName + ". Please ensure that this table exists and is empty!");
        //                return false;
        //            }
        //        }

        //        string[] nonEmptyTables = new string[] {
        //            BaseSecurityOperations.tnDisplay,
        //            BaseSecurityOperations.tnFunctionality,
        //            BaseSecurityOperations.tnXrefGroupsDisplay,
        //            BaseSecurityOperations.tnXrefGroupsFunctionality};
        //        for (int i = 0; i < nonEmptyTables.Length; i++)
        //        {
        //            if (db.GetCount(nonEmptyTables[i]) < 1)
        //            {
        //                Logger.LogWarning("New security model table " + nonEmptyTables[i] + " is empty in database " + dbName + ". Please ensure that this table exists and is populated before running the application!");
        //            }
        //        }

        //        bool isUsersMigrated = MigrateUsers(db, LEGACY_SECURITY_TABLENAME, BaseSecurityOperations.tnUsers);
        //        if (!isUsersMigrated)
        //        {
        //            Logger.LogError("Failed to populate the users table!");
        //        }

        //        Logger.Log("Populating the db security content table ...");
        //        bool isContentPopulated = ContentAdministration.RefreshContentTable(Lcf);
        //        if (!isContentPopulated)
        //        {
        //            Logger.LogError("Failed to populate the db security content table!");
        //        }

        //        isMigrated = isUsersMigrated && isContentPopulated;
        //    }
        //    catch (Exception ex)
        //    {
        //        Logger.LogError("Problem migrating security model in database " + dbName + " at " + ex.StackTrace);
        //        isMigrated = false;
        //    }
        //    finally
        //    {
        //        if (db != null)
        //            db.Disconnect();
        //    }

        //    return isMigrated;
        //}

        //public bool MigrateUsers(DatabaseInformation db, string legacyUsersTable, string newUsersTable)
        //{
        //    bool isMigrated = false;
        //    bool success = false;

        //    UserOperations userHelper = null;

        //    try
        //    {
        //        db.ExecuteSQL("ALTER TABLE " + newUsersTable + @" AUTO_INCREMENT=1", ref success);

        //        userHelper = new UserOperations(Lcf);

        //        Logger.Log("Migrating users from table " + legacyUsersTable + " to table " + newUsersTable + " ...");

        //        List<MGUser> mgUsers = userHelper.GetUsersFromLegacyTable(legacyUsersTable, LEGACY_USER_TABLE_COLUMN_CSV);
        //        if (mgUsers == null)
        //        {
        //            Logger.LogError("Failed to get a list of MGUser objects from the legacy table. Abandoning migration ...");
        //            return false;
        //        }

        //        if (mgUsers.Count == 0)
        //        {
        //            Logger.LogError("Got a list of zero MGUser objects from the legacy table. Abandoning migration ...");
        //            return false;
        //        }

        //        Logger.Log("Got a list of " + mgUsers.Count + " MGUser objects from the legacy table. Migrating them ...");

        //        DateTime currentDateTime = DateTime.Now;
        //        string strCurrentDateTime = DateTimeInformation.FormatDatabaseDate(currentDateTime, true, true);

        //        int totalLogins = 0;
        //        string lastLogin = "NULL";
        //        string lastIP = "NULL";
        //        string lastBrowser = "NULL";
        //        int numIncorrectLogins = 0;

        //        isMigrated = true;
        //        foreach (MGUser user in mgUsers)
        //        {
        //            if (user == null)
        //            {
        //                Logger.LogWarning("NULL user detected, skipping it ...");
        //                continue;
        //            }

        //            if (user.Username == null)
        //            {
        //                Logger.LogWarning("User with NULL username detected, skipping it ...");
        //                continue;
        //            }

        //            bool isInserted = userHelper.InsertUser(user.Username, user.Email, user.Password, user.JobTitle, user.Organisation, user.Telephone, newUsersTable);
        //            if (!isInserted)
        //            {
        //                Logger.LogError("Failed to migrate user with source table ID " + user.ID);
        //                isMigrated = false;
        //            }

        //            totalLogins = 0;
        //            lastLogin = "NULL";
        //            lastIP = "NULL";
        //            lastBrowser = "NULL";
        //            numIncorrectLogins = 0;

        //            if (user.TotalLogins > 0)
        //                totalLogins = user.TotalLogins;

        //            if (user.LastLogin != DateTime.MaxValue && user.LastLogin != DateTime.MinValue)
        //                lastLogin = "'" + DateTimeInformation.FormatDatabaseDate(user.LastLogin, true, true) + "'";
        //            else
        //                lastLogin = "NULL";

        //            if (user.LastIP != null)
        //                lastIP = "'" + user.LastIP + "'";

        //            if (user.LastBrowser != null)
        //                lastBrowser = "'" + user.LastBrowser + "'";

        //            if (user.NumIncorrectLogins > 0)
        //                numIncorrectLogins = user.NumIncorrectLogins;


        //            int updates = db.ExecuteSQL("UPDATE " + newUsersTable + " SET TotalLogins=" + totalLogins + ", LastLoginDate=" + lastLogin + ", LastIP=" + lastIP + ", LastBrowser=" + lastBrowser + ", NumberOfIncorrectLogins=" + numIncorrectLogins + ", StartDate='" + strCurrentDateTime + "' WHERE username='" + user.Username + "';", ref success);
        //        }


        //        int llupdates = db.ExecuteSQL("UPDATE " + newUsersTable + " SET LastLoginDate=NULL WHERE LastLoginDate='0000-00-00 00:00:00';", ref success);

        //        Logger.Log("Dropping the PK auto_inc from table " + newUsersTable + " ...");
        //        int dropKeyUpdates = db.ExecuteSQL("ALTER TABLE " + newUsersTable + " MODIFY COLUMN `ID` INTEGER UNSIGNED NOT NULL DEFAULT 0, DROP PRIMARY KEY;", ref success);

        //        int idUpdates = db.ExecuteSQL("UPDATE " + newUsersTable + " n, " + legacyUsersTable + " o SET n.ID=o.UserID WHERE n.Username = o.Username;", ref success);
        //        if (idUpdates < 1)
        //        {
        //            Logger.LogError("Failed to update the new users table " + newUsersTable + " ID column with the IDs from the legacy table " + legacyUsersTable + "! Please fix this!");
        //            isMigrated = false;
        //        }

        //        Logger.Log("Re-adding the PK auto_inc from table " + newUsersTable + " ...");
        //        int addKeyUpdates = db.ExecuteSQL("ALTER TABLE " + newUsersTable + " MODIFY COLUMN `ID` INTEGER UNSIGNED NOT NULL AUTO_INCREMENT, ADD PRIMARY KEY(`ID`);", ref success);

        //        if (isMigrated)
        //            Logger.Log("Finished succesfully migrating users from table " + legacyUsersTable + " to table " + newUsersTable + ".");
        //        else
        //            Logger.LogError("Failed while migrating users from table " + legacyUsersTable + " to table " + newUsersTable + "!");
        //    }
        //    catch (Exception ex)
        //    {
        //        Logger.LogError("Problem migrating users at " + ex.StackTrace);
        //        isMigrated = false;
        //    }
        //    finally
        //    {
        //        if (userHelper != null)
        //            userHelper.Finish();
        //    }

        //    return isMigrated;
        //}

        #endregion

        #region Static Variables

        public static readonly string APP_NAME = "oldhaminfo3";

        public static readonly string ALL_GROUP_APP_KEY = "all_group_permissions";

        public static readonly string ZLI_GEO_ID_LOOKUP_APP_KEY = "zli_geo_id_app_lookup";

        //public static readonly string LEGACY_SECURITY_TABLENAME = "administrator";

        //public static readonly string LEGACY_USER_TABLE_COLUMN_CSV = "UserID as ID, UserName, JobTitle, Organisation, Telephone, Email, NumberOfIncorrectLogins, TotalLogins, NULL as Description, NULL as StartDate, LastLogin as LastLoginDate, LastIP, LastBrowser, Password";

        #endregion

    }
}
