using System;
using System.Data;
using System.Configuration;
using System.Collections.Generic;
using System.Web.UI.WebControls;
using System.Threading;
using MGL.Data.DataUtilities;
using MGL.DomainModel;
using DataNirvana.Database;

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security {

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Summary description for GroupAdministration
    /// </summary>
    public class GroupAdministration {

        #region !--- Properties ---!
        private ConfigurationInfo lcf = null;
        public ConfigurationInfo Lcf {
            get { return lcf; }
            set { lcf = value; }
        }

        public enum AssociationTypes {
            Assign, UnAssign, NotAssigned
        }

        public enum GroupDeleteTableType {
            Main, XRefContents, XRefDisplay, XRefFunctionality, XRefUsers
        }

        private DatabaseWrapper dbInfo;
        public DatabaseWrapper DbInfo {
            get { return dbInfo; }
            set { dbInfo = value; }
        }
        #endregion

        #region !--- Constructor ---!
        public GroupAdministration(ConfigurationInfo lcf) {
            this.Lcf = lcf;
        }
        #endregion

        #region !--- Methods ---!

        public List<MGGroup> GetAllGroups() {
            bool isFilterOutSuperGroup = false;
            return GetAllGroups(isFilterOutSuperGroup);
        }

        /// <summary>
        /// Gets list of all groups from database.
        /// </summary>
        /// <returns>List of MG Groups</returns>
        public List<MGGroup> GetAllGroups(bool isFilterOutSuperGroup) {
            List<MGGroup> allGroups = null;
            GroupOperations groupHelper = null;
            try {
                groupHelper = new GroupOperations(Lcf);
                allGroups = groupHelper.GetAllGroups(isFilterOutSuperGroup);
                if (allGroups == null) {
                    Logger.LogError(5, "Error getting all groups from system where Filter Super Group is: " + isFilterOutSuperGroup);
                }
                if (allGroups.Count == 0) {
                    Logger.LogWarning("No group found in system. Please check it...! ");
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting all groups from database at: " + ex);
                return null;
            } finally {
                if (groupHelper != null)
                    groupHelper.Finish();
            }
            return allGroups;
        }

        public MGGroup GetGroup(int id) {
            MGGroup result = null;
            GroupOperations groupHelper = null;
            try {
                groupHelper = new GroupOperations(Lcf);
                result = groupHelper.GetGroup(id);
                if (result == null) {
                    Logger.LogWarning("Null Group found in the database for group ID = " + id.ToString());
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting a group given its ID from database at: " + ex);
                return null;
            } finally {
                if (groupHelper != null)
                    groupHelper.Finish();
            }
            return result;

        }

        public MGGroup GetGroup(string name) {
            MGGroup result = null;
            GroupOperations groupHelper = null;
            Logger.Log("Start getting a group from databas where name of group is '" + name + "'.");
            try {
                groupHelper = new GroupOperations(Lcf);
                result = groupHelper.GetGroup(name);
                if (result == null) {
                    Logger.LogWarning("Null Group found in the database for group Name = " + name);
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting a group from databas where name of group is '" + name + "'." + "at: " + ex);
                return null;
            } finally {
                if (groupHelper != null)
                    groupHelper.Finish();
            }
            return result;

        }

        public List<MGGroup> GetDefaultGroups(bool isFilterOutSuperGroup) {
            List<MGGroup> result = null;
            List<MGGroup> allGroups = null;
            Logger.Log("Start getting default groups from system...");
            try {
                result = new List<MGGroup>();
                allGroups = GetAllGroups(isFilterOutSuperGroup);
                if (allGroups == null) {
                    Logger.LogError(5, "Error while trying to get all groups from system. Quitting..!");
                    return null;
                }
                if (allGroups.Count == 0) {
                    Logger.LogWarning("No group is found in the system.");
                    return new List<MGGroup>();
                }
                Logger.Log("Start looping all groups to check which one is default and adding to result list...");

                result = new List<MGGroup>();
                foreach (MGGroup group in allGroups) {
                    if (group.IsDefault) {
                        result.Add(group);
                    }
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Error getting default groups from system at: " + ex);
                return null;
            }
            return result;
        }

        public List<MGGroup> GetAllNonDefaultGroups(bool isFilterOutSuperGroup) {
            List<MGGroup> result = null;
            List<MGGroup> allGroups = null;
            Logger.Log("Start getting all non default groups from system...");
            try {
                result = new List<MGGroup>();
                allGroups = GetAllGroups(isFilterOutSuperGroup);
                if (allGroups == null) {
                    Logger.LogError(5, "Error while trying to get all groups from system. Quitting..!");
                    return null;
                }
                if (allGroups.Count == 0) {
                    Logger.LogWarning("No group is found in the system.");
                    return new List<MGGroup>();
                }
                Logger.Log("Start looping all groups to check which one is not default and adding to result list...");

                result = new List<MGGroup>();
                foreach (MGGroup group in allGroups) {
                    if (!group.IsDefault) {
                        result.Add(group);
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting default groups from system at: " + ex);
                return null;
            }
            return result;

        }

        public List<MGGroup> GetUnassignedGroups(MGUser SelectedUser, List<MGGroup> AssignedUser_Groups) {
            bool isFilterOutSuperGroup = false;
            return GetUnassignedGroups(SelectedUser, AssignedUser_Groups, isFilterOutSuperGroup);
        }

        public List<MGGroup> GetUnassignedGroups(MGUser SelectedUser, List<MGGroup> AssignedUser_Groups, bool isFilterOutSuperGroup) {
            if (SelectedUser == null) {
                Logger.LogError(5, "Null MG User is selected and passed. Quitting..");
                return null;
            }
            if (AssignedUser_Groups == null) {
                Logger.LogError(5, "Null list of assigned MG User is selected and passed. Quitting..");
                return null;
            }

            List<MGGroup> unAssignedGroups = null;
            try {
                //First Get All Groups
                List<MGGroup> allGroups = GetAllGroups();
                if (allGroups == null) {
                    Logger.LogError(5, "Failed to get all groups from system. Quitting");
                    return null;
                }
                unAssignedGroups = new List<MGGroup>();
                foreach (MGGroup group in allGroups) {
                    if (isFilterOutSuperGroup) {
                        if (group.Name != null && group.Name.Equals(GroupAdministration.SUPER_USER_GROUP_NAME, StringComparison.CurrentCultureIgnoreCase)) {
                            continue;
                        }
                    }

                    if (!AssignedUser_Groups.Contains(group)) {
                        unAssignedGroups.Add(group);
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting unassigned groups for user = " + SelectedUser.Username + " at: " + ex);
                return null;
            }

            return unAssignedGroups;
        }

        public string GetError() {
            return MGLSessionSecurityInterface.Instance().SecurityError;
        }

        /// <summary>
        /// Given a MG Group, Add to database
        /// </summary>
        /// <param name="group">Group to add</param>
        /// <returns>Return true if success, false otherwidr</returns>
        public bool AddGroup(MGGroup groupToAdd, out string message) {
            bool isAddSuccess = false;
            message = string.Empty;
            try {
                DbInfo = new DatabaseWrapper(Lcf);

                //Check if group can be added
                if (CheckIfGroupCanBeAdded(groupToAdd, out message)) {
                    //Insert
                    string sql = GroupQB.GetInsertGroupSql(groupToAdd);
                    DbInfo.Connect();
                    bool success = false;
                    if (DbInfo.ExecuteSQL(sql, ref success) == 1) {
                        isAddSuccess = true;
                        message = "Successfully added a group: '" + groupToAdd.Name + "'";
                    } else {
                        message = "Failed to add a group: '" + groupToAdd.Name + "'";
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error adding a group at " + ex);
                message = "Error adding a Group " + groupToAdd.Name + ". Contact MGL.";
                isAddSuccess = false;
            } finally {
                if (isAddSuccess) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }

            return isAddSuccess;
        }

        public bool EditGroup(MGGroup newGroup, out string message) {
            bool isAddSuccess = false;
            message = string.Empty;
            try {
                DbInfo = new DatabaseWrapper(Lcf);
                if (CheckIfGroupCanBeEdited(newGroup, out message)) {
                    //Edit
                    string sql = GroupQB.GetEditGroupSql(newGroup);
                    DbInfo.Connect();
                    bool success = false;
                    if (DbInfo.ExecuteSQL(sql, ref success) == 1) {
                        isAddSuccess = true;
                        message = "Successfully edited group: '" + newGroup.Name + "'";
                    } else {
                        message = "Failed to edit group: '" + newGroup.Name + "'";
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error editing a group at " + ex);
                message = "Error editing a Group " + newGroup.Name + ". Contact MGL.";
                isAddSuccess = false;
            } finally {
                if (isAddSuccess) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return isAddSuccess;
        }

        private bool CheckIfGroupCanBeEdited(MGGroup newGroup, out string message) {
            bool canEdit = true;
            message = "";

            //For given ID, If the new name is same as old Name then check if any of other values is changed
            //If the new Name is not same as that of existing name of same group, then check if the new name already exists for any other group
            MGGroup existingGroup = GetGroup(newGroup.ID);
            if (existingGroup.Name.Equals(newGroup.Name)) {
                if (existingGroup.Description.Equals(newGroup.Description)) {
                    if (existingGroup.IsDefault == newGroup.IsDefault) {
                        message = "All new values are identical to existing values.";
                        canEdit = false;
                    }
                }
            } else if (!CheckIfNewGroupNameIsValidInSystem(newGroup.Name)) {
                message = "The name '" + newGroup.Name + "' is not valid or already exists in the system. Please select another name.";
                canEdit = false;
            }
            return canEdit;
        }

        /// <summary>
        /// Checks if a group can be added.
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        private bool CheckIfGroupCanBeAdded(MGGroup group, out string msg) {
            bool canAdd = true;
            msg = string.Empty;
            try {
                if (group == null || group.Name == null || group.Description == string.Empty) {
                    Logger.LogError(5, "Null or empty value for new group is supplied. Check the inputs.");
                    msg = "Null or empty input value. Please check that there is a valid value for gorup name and description ";
                    return false;
                }
                //Now check if Name is present in the database
                if (!CheckIfNewGroupNameIsValidInSystem(group.Name)) {
                    msg = "The name '" + group.Name + "' is invalid or already exists in the system. Please select another name.";
                    return false;
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error while checking if a group can be added at: " + ex);
                canAdd = false;
            }
            return canAdd;
        }

        /// <summary>
        /// Check if Group Name already exists in the database
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        private bool CheckIfNewGroupNameIsValidInSystem(string groupName) {
            bool isValid = true;
            string sql = "";

            if (groupName == null) {
                Logger.LogError(5, "Cannot check if a NULL groupname already exists in the system!");
                return false;
            }

            if (groupName == String.Empty) {
                Logger.LogError(5, "Cannot check if an empty groupname already exists in the system!");
                return false;
            }

            string groupNameGiven = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, groupName);
            try {
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();
                sql = GroupQB.GetCheckIfAGroupISPresentSql(groupNameGiven);
                IDataReader reader = DbInfo.RunSqlReader(sql);
                while (reader.Read()) {
                    string groupNameFromDB = "";
                    if (reader[GroupQB.GROUP_NAME_COL] != System.DBNull.Value) {
                        groupNameFromDB = (string)reader[GroupQB.GROUP_NAME_COL];
                    } else {
                        Logger.LogError(5, "Got Null Group Name using Sql: " + sql);
                        return false;
                    }

                    groupNameFromDB = DatabaseHelper.SQL_INJECTION_CHECK_PARAMETER(true, groupNameFromDB);
                    if (groupNameFromDB.Equals(groupNameGiven, StringComparison.CurrentCultureIgnoreCase)) {
                        isValid = false;
                    } else {
                        isValid = true;
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error checking if a group name already exists in the system at: " + ex);
                isValid = false;
            } finally {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }

            return isValid;
        }

        ///// <summary>
        ///// Convert ContentItems into a List of ListItems to enable to link to front end.
        ///// </summary>
        ///// <param name="contentItems">List of Content Items</param>
        ///// <returns>List of ListItems</returns>
        //public List<ListItem> GetGroupContentsAsListItem(List<ContentItem> contentItems)
        //{
        //    List<ListItem> result = null;
        //    try
        //    {
        //        if (contentItems == null)
        //        {
        //            Logger.LogWarning("Null of list of contents provided. Quitting !");
        //            return null;
        //        }
        //        if (contentItems.Count == 0)
        //        {
        //            Logger.LogWarning("Empty list of contents provided. Quitting");
        //            result = new List<ListItem>();
        //        }

        //        result = new List<ListItem>();
        //        foreach (ContentItem contentItem in contentItems)
        //        {
        //            ListItem li = new ListItem();

        //            li.Value = contentItem.ID.ToString();

        //            int parentID = contentItem.GetParentID();

        //            if (parentID > 0)
        //            {
        //                li.Value = parentID.ToString() + "_" + li.Value;
        //            }

        //            li.Text = contentItem.Name;
        //            result.Add(li);
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Logger.LogError("Error creating a List<ListItem> from a list of content items at" + ex);
        //        return null;
        //    }
        //    return result;
        //}

        /// <summary>
        /// Given a list of groups, it create a List of ListItems, where each ListItems contains the ID and Name of group.
        /// This is to allow the group names to be displayed onto a list control on web page.
        /// </summary>
        /// <param name="Groups"></param>
        /// <returns></returns>
        public List<ListItem> GetGroupInfoAsListItem(List<MGGroup> Groups) {
            List<ListItem> result = null;
            try {
                if (Groups == null) {
                    Logger.LogWarning("Null of list of groups provided. Quitting !");
                    return null;
                }
                if (Groups.Count == 0) {
                    Logger.LogWarning("Empty list of groups provided.");
                    result = new List<ListItem>();
                }

                result = new List<ListItem>();
                foreach (MGGroup group in Groups) {
                    ListItem li = new ListItem();
                    li.Value = group.ID.ToString();
                    li.Text = group.Name;
                    result.Add(li);
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error creating a List<ListItem> from a list of groups at" + ex);
                return null;
            }
            return result;
        }

        public bool AssignUserToDefaultGroups(int userID) {
            List<int> defaultGroupIDs = GetDefaultGroupIDs();
            if (defaultGroupIDs == null) {
                Logger.LogError(5, "Cannot assign user with ID " + userID + " to default user groups as GetDefaultGroupIDs returned a NULL list!");
                return false;
            } else if (defaultGroupIDs.Count == 0) {
                Logger.LogWarning("Skipping assigning user with ID " + userID + " to default user groups as GetDefaultGroupIDs returned a zero default groups ...");

                return true;
            }

            return AssignUserToGroups(userID, defaultGroupIDs);
        }

        private List<int> GetDefaultGroupIDs() {
            List<int> defaultGroupIDs = null;
            string sql = "";

            try {
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();

                if (!DbInfo.ColumnExists(GroupQB.GROUP_TBLE_NAME, GroupQB.GROUP_DEFAULT_COL)) {
                    Logger.LogError(5, "Column " + GroupQB.GROUP_DEFAULT_COL + " does not exist in table " + GroupQB.GROUP_TBLE_NAME + ". Cannot get default Group IDs!");
                    return null;
                }

                sql = GroupQB.GetSelectDefaultGroupIdsSql();
                defaultGroupIDs = DbInfo.GetIntegerList(sql);
                if (defaultGroupIDs == null) {
                    Logger.LogError(5, "Failed to get default group IDs!");
                    return null;
                }
                if (defaultGroupIDs.Count == 0) {
                    Logger.Log("No default group is found in the system when using SQL " + sql);
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Failed to get default group IDs at: " + ex);
                defaultGroupIDs = null;
            } finally {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return defaultGroupIDs;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     30-Jan-2015 - added the bool toggle on whether or not to use the session wrapper.  This causes an issue with threaded applications as in the
        ///     worker thread the session wrappers are not available.
        /// </summary>
        public bool AssignUserToGroups(int userID, List<int> groupsIDs, bool recordModificationInSessionWrapper) {
            return ChangeGroupToUserAssociation(userID, groupsIDs, AssociationTypes.Assign, recordModificationInSessionWrapper);
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------
        public bool AssignUserToGroups(int userID, List<int> groupsIDs) {
            // the default case ...
            return ChangeGroupToUserAssociation(userID, groupsIDs, AssociationTypes.Assign, true);
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Change the group association for a given user.
        ///     It can assign the groups to a user and also can un assign groups linked to a user.
        ///     30-Jan-2015 - added the bool toggle on whether or not to use the session wrapper.  This causes an issue with threaded applications as in the
        ///     worker thread the session wrappers are not available.
        /// </summary>
        /// <param name="groupsIDs">Group Ids to Assign or UnAssign</param>
        /// <param name="associationType">Assign or UnAssign</param>
        /// <returns>True if successfull, false other wise</returns>
        public bool ChangeGroupToUserAssociation(int userID, List<int> groupsIDs, AssociationTypes associationType, bool recordModificationInSessionWrapper) {
            bool isChangeSuccess = true;

            DbInfo = new DatabaseWrapper(Lcf);
            string sql = "";
            try {
                DbInfo.Connect();
                foreach (int groupID in groupsIDs) {
                    if (associationType == AssociationTypes.Assign) {
                        sql = GroupQB.GetAssignGroupForUserSql(userID, groupID);
                    } else {
                        sql = GroupQB.GetUnAssignGroupForUserSql(userID, groupID);

                    }
                    bool success = false;
                    int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                    if (numChanged == 0) {
                        isChangeSuccess = false;
                    }
                }

            } catch (Exception ex) {

                Logger.LogError(5, "Error in changing group association at: " + ex);
                isChangeSuccess = false;

            } finally {

                if (isChangeSuccess && recordModificationInSessionWrapper) {

                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;

                    if (DbInfo != null)
                        DbInfo.Disconnect();
                }
            }

            return isChangeSuccess;
        }



        //---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Removes all xref records that link the specified user to any groups.
        ///     30-Jan-2015 - added the bool toggle on whether or not to use the session wrapper.  This causes an issue with threaded applications as in the
        ///     worker thread the session wrappers are not available.
        /// </summary>
        /// <param name="userID">The ID of the user to remove from all groups.</param>
        /// <returns>True if successfull, false otherwise.</returns>
        public bool UnassignAllGroupsFromUser(int userID, bool recordModificationInSessionWrapper) {

            if (userID < 1) {
                Logger.LogError(5, "Cannot UnassignAllGroupsFromUser where userID is not specified!");
                return false;
            }

            bool isSuccess = false;
            DbInfo = new DatabaseWrapper(Lcf);
            string sql = "";
            try {
                DbInfo.Connect();

                sql = GroupQB.GetDeleteUserFromAllGroupsSql(userID);
                if (sql == null) {
                    Logger.LogError(5, "Failed to get SQL to delete user from all groups! Abandoning UnassignAllGroupsFromUser ...");
                    return false;
                }
                bool success = false;
                int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                if (numChanged == 0) {
                    isSuccess = false;
                } else {
                    isSuccess = true;
                }

            } catch (Exception ex) {
                Logger.LogError(5, "Error in changing group association at: " + ex);
                return false;
            } finally {

                if (isSuccess && recordModificationInSessionWrapper) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }

            return isSuccess;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool UnassignAllGroupsFromUser(int userID) {
            // default case is true ....
            return UnassignAllGroupsFromUser(userID, true);
        }

        //---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        public bool DeleteGroup(int groupID) {
            bool isAllDeleted = false;
            bool isMainDeleted = false;
            bool isXrefDeleted = false;
            try {
                Logger.Log("Trying to delete the group entry from main table.");
                isMainDeleted = DeleteGroupFromMain(groupID);
                if (!isMainDeleted) {
                    Logger.LogError(5, "Failed to delete group with id = " + groupID + ". Quitting!");
                    return false;
                }

                isXrefDeleted = DeleteGroupEntryFromXrefTables(groupID);

                if (!isXrefDeleted) {
                    Logger.LogError(5, "Failed to delete records from all Xref Tables for Group with id = " + groupID + ".");
                    return false;
                }

                isAllDeleted = isMainDeleted && isXrefDeleted;

            } catch (Exception ex) {
                Logger.LogError(5, "Error deleting group with id = " + groupID + " at: " + ex);
                return false;
            } finally {
                if (isAllDeleted) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }
            }

            return isAllDeleted;
        }

        private bool DeleteGroupFromMain(int groupID) {
            bool isDeleted = false;
            string sql = "";
            string tableName = "";
            try {
                Logger.Log("Trying to delete the group entry from main table '" + GroupQB.GROUP_TBLE_NAME + "'");

                tableName = GetTableNameForGroup(GroupDeleteTableType.Main);

                sql = GroupQB.GetDelteGroupSql(groupID, tableName, true);
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();
                bool success = false;
                int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                if (numChanged == 0) {
                    isDeleted = false;
                } else {
                    isDeleted = true;
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error deleting the group entry from main table '" + GroupQB.GROUP_TBLE_NAME + "' at: " + ex);
                return false;
            } finally {
                if (isDeleted) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return isDeleted;
        }

        private bool DeleteGroupEntryFromXrefTables(int groupID) {
            bool isDeleted = false;
            bool IsContentDelete = false;
            bool IsDisplayDelete = false;
            bool IsFunctionalityDelete = false;
            bool IsUsersDelete = false;

            try {
                IsContentDelete = DeleteGroupEntryFromXrefTable(groupID, GroupDeleteTableType.XRefContents);
                IsDisplayDelete = DeleteGroupEntryFromXrefTable(groupID, GroupDeleteTableType.XRefDisplay);
                IsFunctionalityDelete = DeleteGroupEntryFromXrefTable(groupID, GroupDeleteTableType.XRefFunctionality);
                IsUsersDelete = DeleteGroupEntryFromXrefTable(groupID, GroupDeleteTableType.XRefUsers);
                isDeleted = IsContentDelete && IsDisplayDelete && IsFunctionalityDelete && IsUsersDelete;

            } catch (Exception ex) {
                Logger.LogError(5, "Error deleting the group entry from Xref tables for Group ID " + groupID + "' at: " + ex);
                return false;
            } finally {
                if (isDeleted) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }
            }

            return isDeleted;
        }

        private bool DeleteGroupEntryFromXrefTable(int groupID, GroupDeleteTableType groupDeleteTableType) {
            bool isDeleted = false;
            int count = -1;
            int countDeleted = -1;
            string tableName = GetTableNameForGroup(groupDeleteTableType);
            string sql = "";

            Logger.Log("Start deleting records from table '" + tableName + "' for group id " + groupID);
            try {
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();

                Logger.Log("Getting records from table '" + tableName + "' for group id " + groupID);
                count = GetRecordsForAGroupFromXref(groupID, tableName);
                if (count > 0) {
                    Logger.Log("Start deleting records from '" + tableName + "' for group id = " + groupID);
                    sql = GroupQB.GetDelteGroupSql(groupID, tableName, false);
                    bool success = false;
                    countDeleted = DbInfo.ExecuteSQL(sql, ref success);
                    if (count == countDeleted) {
                        Logger.Log("Successfully deleted " + count + " records from " + tableName + " for group id = " + groupID);
                        isDeleted = true;
                    } else {
                        Logger.Log("Failed to delte " + count + " records from " + tableName + " for group id = " + groupID);

                    }
                } else if (count == 0) {
                    Logger.Log("No records was found in table '" + tableName + "' for group id " + groupID);
                    return true;
                }

            } catch (Exception ex) {
                Logger.Log("Error deleting records from table '" + tableName + "' for group id " + groupID + " at: " + ex);
                return false;
            } finally {
                if (isDeleted) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }


                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return isDeleted;
        }

        private int GetRecordsForAGroupFromXref(int groupID, string tbleName) {
            int count = -1;
            //            string sql = "";
            string whereClause = GroupQB.GROUP_ID_COL_XREFTBL + " = " + groupID;
            try {
                DbInfo = new DatabaseWrapper(Lcf);
                DbInfo.Connect();
                count = DbInfo.GetCount(tbleName, whereClause);
                if (count == -1) {
                    Logger.LogError(5, "Error getting count from table " + tbleName + " Where " + whereClause);
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error getting count of xref entires for a group with ID = " + groupID + " from table" + tbleName + "' at :" + ex);
                count = -1;
            } finally {
                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return count;
        }

        private string GetTableNameForGroup(GroupDeleteTableType groupDeleteTableType) {
            string tbleName = "";

            if (groupDeleteTableType == GroupAdministration.GroupDeleteTableType.Main) {
                tbleName = GroupQB.GROUP_TBLE_NAME;
            }
            if (groupDeleteTableType == GroupAdministration.GroupDeleteTableType.XRefContents) {
                tbleName = GroupQB.GROUP_CONTENT_XREF_TBL;
            }
            if (groupDeleteTableType == GroupAdministration.GroupDeleteTableType.XRefDisplay) {
                tbleName = GroupQB.GROUP_DISPLAY_XREF_TBL;
            }
            if (groupDeleteTableType == GroupAdministration.GroupDeleteTableType.XRefFunctionality) {
                tbleName = GroupQB.GROUP_FUNCTION_XREF_TBL;
            }
            if (groupDeleteTableType == GroupAdministration.GroupDeleteTableType.XRefUsers) {
                tbleName = GroupQB.GROUP_USER_XREF_TBL;
            }
            return tbleName;
        }

        /// <summary>
        /// Check if a group can be deleted. It check that it is not the last default group.
        /// </summary>
        /// <param name="groupID">Group Id</param>
        /// <param name="msg">Output message</param>
        /// <returns>True if can, false otherwise</returns>
        public bool CanDeleteGroup(int groupID, out string msg) {
            bool canDelete = false;
            MGGroup group = null;
            msg = "";
            try {
                group = new MGGroup();
                group = GetGroup(groupID);
                if (group == null) {
                    msg = "Failed to get group for ID (" + groupID + "). Quitting";
                    Logger.LogError(5, msg);
                    return false;
                }
                //Checking if group if not default
                if (!group.IsDefault) {
                    msg = "Group '" + group.Name + "' is not a 'Default Group' therefore can be deleted.";
                    Logger.Log(msg);
                    return true;
                }
                canDelete = CanDeleteDefaultGroup(group, out msg);

            } catch (Exception ex) {
                msg = "Error checking if gorup with ID (" + groupID + ") can be deleted";
                Logger.LogError(5, msg + " at: " + ex);
                return false;
            }
            return canDelete;
        }

        private bool CanDeleteDefaultGroup(MGGroup group, out string msg) {
            bool canDelte = false;
            List<int> allDefaultGroupsIds = null;
            msg = "";
            try {
                Logger.Log("Getting IDs of all default groups in the system....");
                allDefaultGroupsIds = new List<int>();
                allDefaultGroupsIds = GetDefaultGroupIDs();
                if (allDefaultGroupsIds == null) {
                    msg = "Error getting IDs of all Default Groups in the system. Quitting!";
                    Logger.LogError(5, msg);
                    return false;
                }
                if (allDefaultGroupsIds.Count == 0) {
                    msg = "Can not delete. No default group entry is retreived from system. It is contradictory as the current selected group '" + group.Name + "'is a 'default group'.";
                    Logger.LogError(5, msg);
                    return false;
                }
                if (allDefaultGroupsIds.Count == 1 && allDefaultGroupsIds.Contains(group.ID)) {
                    msg = "Can not delete as the selected group is the only 'Default Group' in the system.";
                    Logger.Log(msg);
                    return false;
                }
                if (allDefaultGroupsIds.Count > 1 && allDefaultGroupsIds.Contains(group.ID)) {
                    msg = "Can delete the selected 'Default Group' as it is not 'the Only' in the system.";
                    Logger.Log(msg);
                    canDelte = true;
                }
            } catch (Exception ex) {
                msg = "Error checking if default gorup '" + group.Name + "' can be deleted";
                Logger.LogError(5, msg + " at: " + ex);
                return false;
            }
            return canDelte;
        }

        /// <summary>
        /// Get Users for a given Group. It populate only (3) three User Information (UserName, JobTitle, Email)
        /// </summary>
        /// <param name="group">Group for which to find users.</param>
        /// <param name="associationTypes">Assigned and Unassigned user to group.</param>
        /// <returns></returns>
        public List<MGUser> GetUsersForAGroup(MGGroup group, string searchString, AssociationTypes associationTypes) {
            List<MGUser> result = null;
            IDataReader reader = null;
            string strUserID = null;
            int userID = -1;
            string sql = "";
            string msgPart = "getting users which are '" + associationTypes + "ed' to Group '" + group.Name + "'";

            bool isLockAcquired = Monitor.TryEnter(UserAdministration.USER_ADMIN_LOCK_OBJ, UserAdministration.USER_ADMIN_LOCK_TIMEOUT);
            if (isLockAcquired) {
                try {
                    Logger.Log("Start " + msgPart);
                    DbInfo = new DatabaseWrapper(Lcf);
                    DbInfo.Connect();
                    sql = GroupQB.GetSelectUsersForAGroupSql(group.ID, searchString, associationTypes);
                    reader = DbInfo.RunSqlReader(sql);
                    if (reader == null) {
                        Logger.LogError(5, "Quitting, failed " + msgPart + " with sql : " + sql);
                        return null;
                    }
                    result = new List<MGUser>();
                    while (reader.Read()) {
                        strUserID = null;
                        userID = -1;
                        MGUser user = new MGUser();

                        //Get USER ID
                        if (reader[GroupQB.USER_ID_GENERAL_COL] != System.DBNull.Value) {
                            strUserID = reader[GroupQB.USER_ID_GENERAL_COL].ToString();
                            if (!int.TryParse(strUserID, out userID)) {
                                userID = -1;
                                Logger.LogError(5, "Error parsing user ID into integer. Quitting");
                                return null;
                            }
                        }
                        user.ID = userID;

                        //Get User Name
                        if (reader[GroupQB.USER_NAME_COL] != System.DBNull.Value) {
                            user.Username = SecureStringWrapper.Encrypt((string)reader[GroupQB.USER_NAME_COL]);
                        } else {
                            Logger.LogWarning("Null or empty User is found for ID =" + user.ID + ". Please check the database!");
                            user.Username = SecureStringWrapper.Encrypt("");
                        }

                        //Get User EMAIL
                        if (reader[GroupQB.USER_EMAIL_COL] != System.DBNull.Value) {
                            user.Email = SecureStringWrapper.Encrypt((string)reader[GroupQB.USER_EMAIL_COL]);
                        } else {
                            Logger.LogWarning("Null or empty Email is found for ID =" + user.ID + ". Please check the database!");
                            user.Email = SecureStringWrapper.Encrypt("");
                        }

                        //Get User Job Title
                        if (reader[GroupQB.USER_JOBTITLE_COL] != System.DBNull.Value) {
                            user.JobTitle = SecureStringWrapper.Encrypt((string)reader[GroupQB.USER_JOBTITLE_COL]);
                        } else {
                            //Logger.LogWarning("Null or empty job title is found for ID =" + user.ID + ". Please check the database!");
                            user.JobTitle = SecureStringWrapper.Encrypt("");
                        }
                        result.Add(user);
                    }
                } catch (Exception ex) {
                    Logger.LogError(5, "Error " + msgPart + " at: " + ex);
                    return null;
                } finally {
                    Monitor.Exit(UserAdministration.USER_ADMIN_LOCK_OBJ);
                    if (reader != null && !reader.IsClosed)
                        reader.Close();
                    if (DbInfo != null)
                        DbInfo.Disconnect();
                }
            } else {
                Logger.LogError(5, "Failed to get exclusive lock in GetUsersForAGroup when " + msgPart);
                return null;
            }

            return result;
        }

        public List<ListItem> GetUserInfoAsListItem(List<MGUser> users) {
            List<ListItem> result = null;
            try {
                if (users == null) {
                    Logger.LogWarning("Null of list of users provided. Quitting !");
                    return null;
                }
                if (users.Count == 0) {
                    Logger.LogWarning("Empty list of users provided.");
                    result = new List<ListItem>();
                }

                result = new List<ListItem>();
                foreach (MGUser user in users) {
                    string desc = "";
                    ListItem li = new ListItem();
                    li.Value = user.ID.ToString();
                    if (user.Username.Length > 0) { // != "")
                        desc = SecureStringWrapper.Decrypt(user.Username).ToString();
                    }
                    if (user.Email.Length > 0) { // != "") {
                        desc += "; " + SecureStringWrapper.Decrypt(user.Email).ToString();
                    }
                    if (user.JobTitle.Length > 0) { // != "") {
                        desc += "; " + SecureStringWrapper.Decrypt(user.JobTitle).ToString();
                    }
                    li.Text = desc;
                    result.Add(li);
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error creating a List<ListItem> from a list of users at" + ex);
                return null;
            }
            return result;
        }

        public bool ChangeUserToGroupAssociation(MGGroup group, List<int> usersIDs, AssociationTypes associationType) {
            bool ISChanged = true;
            DbInfo = new DatabaseWrapper(Lcf);
            string sql = "";
            string partMSG = "'" + associationType + "ing' (" + usersIDs.Count + ") users to Group '" + group.Name + "'";
            try {
                Logger.Log("Start " + partMSG);
                DbInfo.Connect();
                foreach (int userID in usersIDs) {
                    if (associationType == AssociationTypes.Assign) {
                        sql = GroupQB.GetAssignGroupForUserSql(userID, group.ID);
                    } else {
                        sql = GroupQB.GetUnAssignGroupForUserSql(userID, group.ID);

                    }
                    bool success = false;
                    int numChanged = DbInfo.ExecuteSQL(sql, ref success);
                    if (numChanged == 0) {
                        ISChanged = false;
                    }
                }
            } catch (Exception ex) {
                Logger.LogError(5, "Error " + partMSG + " at: " + ex);
                return false;
            } finally {
                if (ISChanged) {
                    SecureContentWrapper.SecurityHasBeenModifiedThisSession = true;
                }

                if (DbInfo != null)
                    DbInfo.Disconnect();
            }
            return ISChanged;
        }

        #endregion

        #region Statics

        public static readonly string SUPER_USER_GROUP_NAME = "SuperAdmin";

        public static string BACK_LINK_PAGE_QUERY_STRING_KEY = "backPage";

        public static string BACK_LINK_TEXT_QUERY_STRING_KEY = "backText";

        #endregion











    }
}