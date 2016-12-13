using System;
using System.Data;
using System.Configuration;
using System.Collections.Generic;
using System.Text;
using MGL.Data.DataUtilities;
using MGL.DomainModel;

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for GroupOperations
    /// </summary>
    internal class GroupOperations : BaseSecurityOperations {

        private static string thisClassName = "MGL.GEDI.Security.GroupOperations";

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public GroupOperations(ConfigurationInfo configFile) : base(configFile, false) {
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------

        public List<MGGroup> GetAllGroups()
        {
            bool isFilterOutSuperGroup = false;

            return GetAllGroups(isFilterOutSuperGroup);
        }


        /// <summary>
        /// Get all groups from database.
        /// It checks if Description or IsDefault Column is missing in the table. If any is missing then skipping it.
        /// </summary>
        /// <param name="isFilterOutSuperGroup">Filter if to filer the supper group</param>
        /// <returns>List of Groups</returns>
        public List<MGGroup> GetAllGroups( bool isFilterOutSuperGroup)
        {
            List<MGGroup> groups = null;
            bool isDescriptionColExists = false;
            bool isIsDefaultColExists = false;
            bool isDescDefaultCols = false;
            bool isDefaultGroup = false;
            string sql = "";

            string msg = "getting all groups from system. Filter supper group =" + isFilterOutSuperGroup;
            Logger.Log("Start " + msg);

            try
            {
                sql = "SELECT ID,GroupName,AllowDataEdit,AllowUserEdit";
                //Checking if Description Column Exists or not
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, DESC_COL_NAME))
                {
                    Logger.Log("Column '" + DESC_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + DESC_COL_NAME;
                    isDescriptionColExists = true;
                }
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, ISDEFAULT_COL_NAME))
                {
                    Logger.Log("Column '" + ISDEFAULT_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + ISDEFAULT_COL_NAME;
                    isIsDefaultColExists = true;
                }
                sql += " FROM " + BaseSecurityOperations.tnGroups;

                //Setting flag if both Column Exists, This will define total number of column in Select Statement and will be read from dbInfo.GetDataList(sql)
                isDescDefaultCols = isDescriptionColExists && isIsDefaultColExists;

                if (isFilterOutSuperGroup)
                {
                    sql += " WHERE GroupName <> '" + GroupAdministration.SUPER_USER_GROUP_NAME + "' ";
                }
                sql += " ORDER BY GroupName;";
                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(8,"Error " + msg + ". Using sql = " + sql);
                    return null;
                }
                if (data.Count == 0)
                {
                    Logger.Log("No group found in the system for sql = " + sql);
                    return groups = new List<MGGroup>();
                }

                groups = new List<MGGroup>();
                Logger.Log("Looping the data list to create list of MGGroups.");

                foreach (string[] row in data)
                {
                    isDefaultGroup = false;


                    bool allowDataEdit = (row[2].Equals("1")) ? true : false;
                    bool allowUserEdit = (row[3].Equals("1")) ? true : false;

                    MGGroup group = new MGGroup(int.Parse(row[0]), row[1], allowDataEdit, allowUserEdit);

                    //If both Description and IsDefault Column exists then total number of column in Select Statement are 6
                    //4th Column is Description
                    //5ht Column is IsDefault
                    if (isDescDefaultCols)
                    {
                        if (row.Length > 4)
                        {
                            if (row[4] != null)
                            {
                                group.Description = row[4];
                            }
                            if (row[5] != null)
                            {
                                isDefaultGroup = (row[5].Equals("1")) ? true : false;
                                group.IsDefault = isDefaultGroup;
                            }
                            else
                            {
                                Logger.LogWarning("Invalid value found for column " + ISDEFAULT_COL_NAME);
                            }
                        }
                    }
                    else
                    {
                        if (isDescriptionColExists)
                        {
                            if (row.Length > 4)
                            {
                                if (row[4] != null)
                                {
                                    group.Description = row[4];
                                }
                            }
                        }
                        if (isIsDefaultColExists)
                        {
                            if (row.Length > 4)
                            {
                                if (row[4] != null)
                                {
                                    isDefaultGroup = (row[4].Equals("1")) ? true : false;
                                    group.IsDefault = isDefaultGroup;
                                }
                            }
                        }
                    }
                    groups.Add(group);
                }
//                Logger.LogList = dbInfo.GetErrors(), thisClassName, "GetAllFeatures");
            }
            catch (Exception ex)
            {
                Logger.LogError(8, "Error " + msg + ". At " + ex);
                Logger.LogError(8, thisClassName + " GetAllGroups:" + ex.ToString());
                return null;
            }
            return groups;
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public List<int> GetGuestGroups()
        {
            string sqlQuery = "SELECT ID FROM " + tnGroups + " WHERE GroupName='Guest';";
            List<int> guestGroups = dbInfo.GetIntegerList(sqlQuery);
            if (guestGroups == null)
            {
                guestGroups = new List<int>();
            }
            return guestGroups;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public MGGroup GetGroup(string groupName)
        {

            MGGroup group = null;
            string sql = "";
            bool isDescriptionColExists = false;
            bool isIsDefaultColExists = false;
            bool isDescDefaultCols = false;

            string msg = "getting group from system where given Group name = " + groupName;
            Logger.Log("Start " + msg);

            try
            {
                sql = "SELECT ID,GroupName,AllowDataEdit,AllowUserEdit";
                //Checking if Description Column Exists or not
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, DESC_COL_NAME))
                {
                    Logger.Log("Column '" + DESC_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + DESC_COL_NAME;
                    isDescriptionColExists = true;
                }
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, ISDEFAULT_COL_NAME))
                {
                    Logger.Log("Column '" + ISDEFAULT_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + ISDEFAULT_COL_NAME;
                    isIsDefaultColExists = true;
                }
                sql += " FROM " + BaseSecurityOperations.tnGroups;

                //Setting flag if both Column Exists, This will define total number of column in Select Statement and will be read from dbInfo.GetDataList(sql)
                isDescDefaultCols = isDescriptionColExists && isIsDefaultColExists;
                sql += " WHERE GroupName = '" + groupName + "';";

                string[] row = dbInfo.GetDataSingleRecord(sql);

                if (row == null)
                {
                    Logger.LogError(5, "Error " + msg + ". Using sql = " + sql);
                    return null;
                }
                if (row.Length == 0)
                {
                    Logger.Log("No group found in the system for sql = " + sql);
                    return group = new MGGroup();
                }

                Logger.Log("Creating a group object and setting properties.");

                bool allowDataEdit = (row[2].Equals("1")) ? true : false;
                bool allowUserEdit = (row[3].Equals("1")) ? true : false;

                group = new MGGroup(int.Parse(row[0]), row[1], allowDataEdit, allowUserEdit);

                //If both Description and IsDefault Column exists then total number of column in Select Statement are 6
                //4th Column is Description
                //5ht Column is IsDefault

                bool isDefaultGroup = false;
                if (isDescDefaultCols)
                {
                    if (row.Length > 4)
                    {
                        if (row[4] != null)
                        {
                            group.Description = row[4];
                        }
                        if (row[5] != null)
                        {
                            isDefaultGroup = (row[5].Equals("1")) ? true : false;
                            group.IsDefault = isDefaultGroup;
                        }
                        else
                        {
                            Logger.LogWarning("Invalid value found for column " + ISDEFAULT_COL_NAME);
                        }
                    }
                }
                else
                {
                    if (isDescriptionColExists)
                    {
                        if (row.Length > 4)
                        {
                            if (row[4] != null)
                            {
                                group.Description = row[4];
                            }
                        }
                    }
                    if (isIsDefaultColExists)
                    {
                        if (row.Length > 4)
                        {
                            if (row[4] != null)
                            {
                                isDefaultGroup = (row[4].Equals("1")) ? true : false;
                                group.IsDefault = isDefaultGroup;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error " + msg + ex);
                return null;
            }
            return group;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------


        /// <summary>
        /// Get a group from database given group ID.
        /// It checks if Description or IsDefault Column is missing in the table. If any is missing then skipping it.
        /// </summary>
        /// <returns>Group Object</returns>
        public MGGroup GetGroup(int groupID)
        {
            MGGroup group = null;
            string sql = "";
            bool isDescriptionColExists = false;
            bool isIsDefaultColExists = false;
            bool isDescDefaultCols = false;

            string msg = "getting group from system where Group ID = " + groupID;
            Logger.Log("Start " + msg);

            try
            {
                sql = "SELECT ID,GroupName,AllowDataEdit,AllowUserEdit";
                //Checking if Description Column Exists or not
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, DESC_COL_NAME))
                {
                    Logger.Log("Column '" + DESC_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + DESC_COL_NAME;
                    isDescriptionColExists = true;
                }
                if (dbInfo.ColumnExists(BaseSecurityOperations.tnGroups, ISDEFAULT_COL_NAME))
                {
                    Logger.Log("Column '" + ISDEFAULT_COL_NAME + "' exists in the table '" + BaseSecurityOperations.tnGroups + "'. Adding to sql...");
                    sql += "," + ISDEFAULT_COL_NAME;
                    isIsDefaultColExists = true;
                }
                sql += " FROM " + BaseSecurityOperations.tnGroups;

                //Setting flag if both Column Exists, This will define total number of column in Select Statement and will be read from dbInfo.GetDataList(sql)
                isDescDefaultCols = isDescriptionColExists && isIsDefaultColExists;
                sql += " WHERE ID = '" + groupID + "';";
                string[] row = dbInfo.GetDataSingleRecord(sql);

                if (row == null)
                {
                    Logger.LogError(5, "Error " + msg + ". Using sql = " + sql);
                    return null;
                }
                if (row.Length == 0)
                {
                    Logger.Log("No group found in the system for sql = " + sql);
                    return group = new MGGroup();
                }

                Logger.Log("Creating a group object and setting properties.");

                bool allowDataEdit = (row[2].Equals("1")) ? true : false;
                bool allowUserEdit = (row[3].Equals("1")) ? true : false;

                group = new MGGroup(int.Parse(row[0]), row[1], allowDataEdit, allowUserEdit);

                //If both Description and IsDefault Column exists then total number of column in Select Statement are 6
                //4th Column is Description
                //5ht Column is IsDefault

                bool isDefaultGroup = false;
                if (isDescDefaultCols)
                {
                    if (row.Length > 4)
                    {
                        if (row[4] != null)
                        {
                            group.Description = row[4];
                        }
                        if (row[5] != null)
                        {
                            isDefaultGroup = (row[5].Equals("1")) ? true : false;
                            group.IsDefault = isDefaultGroup;
                        }
                        else
                        {
                            Logger.LogWarning("Invalid value found for column " + ISDEFAULT_COL_NAME);
                        }
                    }
                }
                else
                {
                    if (isDescriptionColExists)
                    {
                        if (row.Length > 4)
                        {
                            if (row[4] != null)
                            {
                                group.Description = row[4];
                            }
                        }
                    }
                    if (isIsDefaultColExists)
                    {
                        if (row.Length > 4)
                        {
                            if (row[4] != null)
                            {
                                isDefaultGroup = (row[4].Equals("1")) ? true : false;
                                group.IsDefault = isDefaultGroup;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error " + msg + ex);
                return null;
            }
            return group;
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private MGGroup GetGroup(string[] row) {
            return null;
        }

        public List<MGSecurityTag> GetUnassignedAnyGroupContentDictionary()
        {
            // This gets permissions that are NOT assigned to ANY group:
            // TODO: generate this query in a method that can be called for all three types of group permission (content, display & functionality)

            List<MGSecurityTag> groupTags = null;
            string sql = "";
            try
            {
                sql = GroupQB.GetSelectGroupContentPermissionSql(MGGroup.NO_GROUP_GROUP_ID, GroupAdministration.AssociationTypes.NotAssigned);
                // TODO: make this checking and single list from single entry dictionary retrieval into a method

                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(5, "Failed to get the conents from database which are not linked to any group using SQL = " + sql);
                    return null;
                }
                else if (data.Count == 0)
                {
                    return new List<MGSecurityTag>();
                }
                //return BuildSecurityDictionary(data)[MGGroup.NO_GROUP_GROUP_ID];

                Dictionary<int, List<MGSecurityTag>> dict = BuildSecurityDictionary(data);
                if (dict == null )
                {
                    Logger.LogError(5, "Error converting into Dictionary the contents permission which not linked to any group.");
                    return null;
                }
                else if (dict.Count == 0)
                {
                    Logger.Log("Got zero unassigned to any group content items, returning an empty list of security tags ...");
                    return new List<MGSecurityTag>();
                }
                else if (dict.Count > 1)
                {
                    Logger.LogError(5, "Invalid number of entries are found in the Dictionary for contents permission which not linked to any group.");
                    Logger.LogError(5, "Every content is set to belong to a dumy Group with ID = 1. Therefore there should be only one entry in the dictionary.");
                    return null;
                }
                else if (!dict.ContainsKey(MGGroup.NO_GROUP_GROUP_ID))
                {
                    Logger.LogError(5, "Dictionary does not containd the contents entries for the dumy group.");
                    return null;
                }

                groupTags = dict[MGGroup.NO_GROUP_GROUP_ID];
                if (groupTags == null)
                {
                    Logger.LogError(5, "Could not find the MGSecurityTag for " + MGGroup.NO_GROUP_GROUP_NAME);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error Getting Content Permission Information for Contents which are not linked to any group at " + ex);
                return null;
            }
            return groupTags;
        }



        public List<MGSecurityTag> GetGroupContentDictionary(int groupID)
        {
            return GetGroupContentDictionary(groupID, GroupAdministration.AssociationTypes.Assign);
        }


        /// <summary>
        /// Getting Group to Contenet Permission Information
        /// </summary>
        /// <param name="groupID">Group ID to get permission for.</param>
        /// <param name="associationType">Assign, UnAssign, NotAssigned</param>
        /// <returns>List of MGSecurityTag </returns>
        public List<MGSecurityTag> GetGroupContentDictionary(int groupID, GroupAdministration.AssociationTypes associationType)
        {

            List<MGSecurityTag> groupTags = null;
            string sql = null;
            Logger.Log("Start getting the group to content dictionary given a group id and assiciation type.");

            try
            {
                sql = GroupQB.GetSelectGroupContentPermissionSql(groupID, associationType);

                // TODO: make this checking and single list from single entry dictionary retrieval into a method
                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(5, "Error getting group to content permissions for sql: " + sql);
                    return null;
                }
                else if (data.Count == 0)
                {
                    Logger.Log("No record was found in the database for sql :" + sql);
                    return new List<MGSecurityTag>();
                }

                Logger.Log("Start building the Security Dictionary.");
                bool isCheckForUniqVals = false;
                Dictionary<int, List<MGSecurityTag>> dict = BuildSecurityDictionary(data, isCheckForUniqVals);
                if (dict == null)
                {
                    Logger.LogError(5, "Error, got Null Security Dictionary. Quitting!");
                    return null;
                }
                else if (dict.Count == 0)
                {
                    Logger.LogError(5, "Error, got Empty Security Dictionary. Quitting!");
                    return null;
                }
                else if (dict.Count > 1)
                {
                    Logger.LogError(5, "TODO: write log");
                    return null;
                }
                else if (!dict.ContainsKey(groupID))
                {
                    Logger.LogError(5, "Error, required group id is not found in the Security Dictionary. Quitting!");
                    return null;
                }

                Logger.Log("Start Getting Security Tag.");
                groupTags = dict[groupID];
                if (groupTags == null)
                {
                    Logger.LogError(5, "Error, Null Security Tag found. Quitting!");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error Getting Group to Content Permission Information at " + ex);
                return null;
            }
            return groupTags;
        }

        /// <summary>
        /// Getting Group to Functionality Permission Information
        /// </summary>
        /// <param name="groupID">Group ID to get permission for.</param>
        /// <param name="associationType">Assign, UnAssign, NotAssigned</param>
        /// <returns>List of MGSecurityTag</returns>
        public List<MGSecurityTag> GetGroupFunctionalityDictionary(int groupID, GroupAdministration.AssociationTypes associationType)
        {

            List<MGSecurityTag> groupTags = null;
            string sql = null;
            bool addIDcol = false;
            bool addDescCol = false;

            Logger.Log("Start getting the group to functionality dictionary for group id = " + groupID +" and assiciation type.");
            try
            {
                if (dbInfo.ColumnExists(GroupQB.FUNCTION_TBLE_NAME, "ID"))
                {
                    addIDcol = true;
                }
                if (dbInfo.ColumnExists(GroupQB.FUNCTION_TBLE_NAME, "Description"))
                {
                    addDescCol = true;
                }
                sql = GroupQB.GetSelectGroupFunctionPermissionSql(groupID, addIDcol, addDescCol, associationType);

                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(5, "Error getting group to functionality permissions for sql: " + sql);
                    return null;
                }
                else if (data.Count == 0)
                {
                    Logger.Log("No record was found in the database for sql :" + sql);
                    return new List<MGSecurityTag>();
                }

                Logger.Log("Start building the Security Dictionary.");
                Dictionary<int, List<MGSecurityTag>> dict = BuildSecurityDictionary(data);
                if (dict == null)
                {
                    Logger.LogError(5, "Error, got Null Security Dictionary when getting group to functionality dictionary . Quitting!");
                    return null;
                }
                else if (dict.Count == 0)
                {
                    Logger.LogError(5, "Error, got Empty Security Dictionary when getting group to functionality dictionary. Quitting!");
                    return null;
                }
                else if (dict.Count > 1)
                {
                    Logger.LogError(5, "Invalid number of entries forud in the Security Dictionary when getting group to functionality dictionary");
                    return null;
                }
                else if (!dict.ContainsKey(groupID))
                {
                    Logger.LogError(5, "Error, required group id is not found in the Security Dictionary. Quitting!");
                    return null;
                }

                Logger.Log("Start Getting Security Tag when Getting group to functionality dictionary.");
                groupTags = dict[groupID];
                if (groupTags == null)
                {
                    Logger.LogError(5, "Error, Null Security Tag found when getting group to functionality dictionary. Quitting!");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error Getting Group to Functionality Permission Information at " + ex);
                return null;
            }
            return groupTags;
        }

        public Dictionary<string, string> GetFunctionalityDescriptionDictionary()
        {
            Dictionary<string, string> funcDescs = null;
            string sql = null;

            Logger.Log("Getting the functionality description dictionary ...");
            try
            {
                sql = GroupQB.GetSelectFunctionDescriptionSql();

                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(5, "Error getting functionality description for data sql: " + sql);
                    return null;
                }
                else if (data.Count == 0)
                {
                    Logger.Log("No record was found in the database for sql :" + sql);
                    return new Dictionary<string, string>();
                }

                string functionalityEnumString = null;
                SecureRequestContext.FunctionalityType functionalityEnumVal = SecureRequestContext.FunctionalityType.UNKNOWN;
                string functionalityDesc = null;
                funcDescs = new Dictionary<string, string>();
                foreach (string[] row in data)
                {
                    functionalityEnumString = row[0];
                    functionalityDesc = row[1];

                    try
                    {
                        functionalityEnumVal =
                            (SecureRequestContext.FunctionalityType)
                                Enum.Parse(typeof(SecureRequestContext.FunctionalityType),
                                    functionalityEnumString);
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(5, "Error parsing Functionality Enum String at " + ex);
                        functionalityEnumVal = SecureRequestContext.FunctionalityType.UNKNOWN;
                    }

                    if(functionalityEnumVal != SecureRequestContext.FunctionalityType.UNKNOWN &&
                       !funcDescs.ContainsKey(functionalityEnumString) &&
                        functionalityDesc != null)
                    {
                        funcDescs.Add(functionalityEnumString, functionalityDesc);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error Getting Functionality description dictionary at " + ex);
                return null;
            }

            return funcDescs;
        }


        /// <summary>
        /// Getting Group to Display Permission Information
        /// </summary>
        /// <param name="groupID">Group ID to get permission for.</param>
        /// <param name="associationType">Assign, UnAssign, NotAssigned</param>
        /// <returns>List of MGSecurityTag</returns>
        public List<MGSecurityTag> GetGroupDisplayDictionary(int groupID, GroupAdministration.AssociationTypes associationType)
        {

            List<MGSecurityTag> groupTags = null;
            string sql = null;
            bool addIDcol = false;
            bool addDescCol = false;

            Logger.Log("Start getting the group to display dictionary for group id = " + groupID + " and assiciation type.");
            try
            {
                if (dbInfo.ColumnExists(GroupQB.DISPLAY_TBLE_NAME, "ID")){
                    addIDcol = true;
                }
                if (dbInfo.ColumnExists(GroupQB.DISPLAY_TBLE_NAME, "Description")){
                    addDescCol = true;
                }
                sql = GroupQB.GetSelectGroupDisplayPermissionSql(groupID, addIDcol, addDescCol, associationType);

                List<string[]> data = dbInfo.GetDataList(sql);
                if (data == null)
                {
                    Logger.LogError(5, "Error getting group to display permissions for sql: " + sql);
                    return null;
                }
                else if (data.Count == 0)
                {
                    Logger.Log("No record was found in the database for sql :" + sql);
                    return new List<MGSecurityTag>();
                }
                Logger.Log("Start building the Security Dictionary.");
                Dictionary<int, List<MGSecurityTag>> dict = BuildSecurityDictionary(data);
                if (dict == null)
                {
                    Logger.LogError(5, "Error, got Null Security Dictionary when getting group to display dictionary . Quitting!");
                    return null;
                }
                else if (dict.Count == 0)
                {
                    Logger.LogError(5, "Error, got Empty Security Dictionary when getting group to display dictionary. Quitting!");
                    return null;
                }
                else if (dict.Count > 1)
                {
                    Logger.LogError(5, "Invalid number of entries forud in the Security Dictionary when getting group to display dictionary");
                    return null;
                }
                else if (!dict.ContainsKey(groupID))
                {
                    Logger.LogError(5, "Error, required group id is not found in the Security Dictionary when getting group to display dictionary. Quitting!");
                    return null;
                }

                Logger.Log("Start Getting Security Tag when Getting group to display dictionary.");
                groupTags = dict[groupID];
                if (groupTags == null)
                {
                    Logger.LogError(5, "Error, Null Security Tag found when getting group to display dictionary. Quitting!");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error Getting Group to display Permission Information at " + ex);
                return null;
            }
            return groupTags;

            //// TODO: make this safe
            //return BuildSecurityDictionary(data)[groupID];
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public Dictionary<int, List<MGSecurityTag>> GroupContentDictionary()
        {
            string idCol = String.Empty;
            if (dbInfo.ColumnExists(tnContent, "ID"))
                idCol = ",b.ID";

            string descCol = String.Empty;
            if (dbInfo.ColumnExists(tnContent, "Description"))
                descCol = ",b.Description";

            string sql = "SELECT a.GroupID, b.FeatureName, b.FeatureValue " + idCol + descCol + " FROM " + tnXrefGroupsContent + " a, " + tnContent + " b WHERE a.FeatureID=b.ID;";

            List<string[]> data = dbInfo.GetDataList(sql);
            if (data.Count == 0)
            {
                Logger.LogWarning("Got empty group to content dictionary!");
                return new Dictionary<int, List<MGSecurityTag>>();
            }

            return BuildSecurityDictionary(data);
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public Dictionary<int, List<MGSecurityTag>> GroupFunctionalityDictionary() {

            string idCol = String.Empty;
            if (dbInfo.ColumnExists(tnFunctionality, "ID"))
                idCol = ",b.ID";

            string descCol = String.Empty;
            if (dbInfo.ColumnExists(tnFunctionality, "Description"))
                descCol = ",b.Description";

            string sql = "SELECT a.GroupID, b.FeatureName, b.FeatureValue " + idCol + descCol + " FROM " + tnXrefGroupsFunctionality + " a, " + tnFunctionality + " b WHERE a.FeatureID=b.ID;";

            List<string[]> data = dbInfo.GetDataList(sql);
            if (data.Count == 0)
            {
                Logger.LogWarning("Got empty group to functionality dictionary!");
                return new Dictionary<int, List<MGSecurityTag>>();
            }

            return BuildSecurityDictionary(data);
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------------
        public Dictionary<int, List<MGSecurityTag>> GroupDisplayDictionary() {

            string idCol = String.Empty;
            if (dbInfo.ColumnExists(tnDisplay, "ID"))
                idCol = ",b.ID";

            string descCol = String.Empty;
            if (dbInfo.ColumnExists(tnDisplay, "Description"))
                descCol = ",b.Description";

            string sql = "SELECT a.GroupID, b.FeatureName, b.FeatureValue " + idCol + descCol + " FROM " + tnXrefGroupsDisplay + " a, " + tnDisplay + " b WHERE a.FeatureID=b.ID;";

            List<string[]> data = dbInfo.GetDataList(sql);
            if (data.Count == 0)
            {
                Logger.LogWarning("Got empty group to display dictionary!");
                return new Dictionary<int, List<MGSecurityTag>>();
            }

            return BuildSecurityDictionary(data);
        }


       public static readonly string ISDEFAULT_COL_NAME = "IsDefault";
       public static readonly string DESC_COL_NAME = "Description";
    }

}