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
using MGL.DomainModel;
using MGL.Data.DataUtilities;

namespace MGL.Security
{

    /// <summary>
    /// A class for providing access to the security context of a user.
    /// </summary>
    public class UserSecurityContext
    {

        #region Properties

        private ConfigurationInfo lcf = null;
        /// <summary>
        /// The configuration file for the user security context.
        /// Specifies which DB the user security tables are in.
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

        private MGUser currentUser = null;
        /// <summary>
        /// The User object for the current user.
        /// </summary>
        public MGUser CurrentUser
        {
            get
            {
                return currentUser;
            }
            set
            {
                currentUser = value;
            }
        }

        private List<MGGroup> currentUserGroups = null;
        /// <summary>
        /// The Groups the current User belongs to.
        /// </summary>
        public List<MGGroup> CurrentUserGroups
        {
            get
            {
                return currentUserGroups;
            }
            set
            {
                currentUserGroups = value;
            }
        }

        private List<GroupPermissions> currentUserGroupPermissions = null;
        /// <summary>
        /// This contains the Users UserGroups and their associated permissions.
        /// </summary>
        public List<GroupPermissions> CurrentUserGroupPermissions
        {
            get
            {
                return currentUserGroupPermissions;
            }
            set
            {
                currentUserGroupPermissions = value;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new empty UserSecurityContext.
        /// </summary>
        public UserSecurityContext(ConfigurationInfo lcf)
        {
            this.Lcf = lcf;
        }

        #endregion

        #region Static Methods

        public static UserSecurityContext GetCurrentUserSecurityContext(AppSecurityContext appSecContext)
        {
            UserSecurityContext currentUserSecContext = new UserSecurityContext(appSecContext.Lcf);

            currentUserSecContext.CurrentUser = Authorisation.CurrentUser;

            if (currentUserSecContext.CurrentUser != null)
            {
                currentUserSecContext.CurrentUserGroups = currentUserSecContext.GetUserGroups(currentUserSecContext.CurrentUser);
                currentUserSecContext.CurrentUserGroupPermissions = currentUserSecContext.GetUserGroupPermissions(currentUserSecContext.CurrentUserGroups, appSecContext);
            }

            return currentUserSecContext;
        }

        public List<GroupPermissions> GetUserGroupPermissions(
            List<MGGroup> userGroups,
            AppSecurityContext appSecContext)
        {
            if (userGroups == null)
            {
                Logger.LogError(5, "Cannot get UserGroupPermissions for NULL userGroups list!");
                return null;
            }

            List<GroupPermissions> userGroupPermissions = new List<GroupPermissions>();

            if (userGroups.Count == 0)
            {
                Logger.LogWarning("UserGroup List is empty, returning empty UserGroupPermissionsList!");
                return userGroupPermissions;
            }

            if (appSecContext == null)
            {
                Logger.LogError(5, "Cannot get UserGroupPermissions with NULL AppSecurityContext!");
                return null;
            }

            // Store appSecContext.AllGroupPermissions locally so we only read it once from DB.
            // TODO: if the Staging database context, read the permissions only for this group.
            bool isUsingStagingDb =
                (Lcf.DbConInfo.NAME == AppSecurityContext.StagingDbLcf.DbConInfo.NAME);

            Dictionary<int, GroupPermissions> allGroupPerms = null;

            if (!isUsingStagingDb)
            {
                allGroupPerms = appSecContext.AllGroupPermissions;
                if (allGroupPerms == null)
                {
                    Logger.LogError(5, "Cannot get UserGroupPermissions with NULL AppSecurityContext.AllGroupPermissions!");
                    return null;
                }
                if (allGroupPerms.Count == 0)
                {
                    Logger.LogError(5, "AppSecurityContext.AllGroupPermissions is empty, returning empty UserGroupPermissionsList!");
                    return userGroupPermissions;
                }
            }

            GroupPermissions groupPerms = null;
            foreach (MGGroup userGroup in userGroups)
            {
                if (userGroup == null)
                {
                    Logger.LogError(5, "NULL UserGroup detected, skipping it ...");
                    continue;
                }
                else if (userGroup.ID < 1)
                {
                    Logger.LogError(5, "Invalid UserGroup.ID detected, skipping it ...");
                    continue;
                }

                if (!isUsingStagingDb)
                {
                    if (!allGroupPerms.ContainsKey(userGroup.ID))
                    {
                        Logger.LogError(5, "UserGroup.ID " + userGroup.ID + " not present in AppSecurityContext.AllGroupPermissions, skipping it ...");
                        continue;
                    }

                    groupPerms = allGroupPerms[userGroup.ID];
                    if (groupPerms == null)
                    {
                        Logger.LogError(5, "NULL GroupPermissions for userGroup.ID = " + userGroup.ID + " detected, skipping adding it ...");
                        continue;
                    }
                }
                else
                {
                    groupPerms = appSecContext.GetGroupPermissions(userGroup);
                }

                if (userGroupPermissions.Contains(groupPerms))
                {
                    Logger.LogError(5, "GroupPermissions for userGroup.ID = " + userGroup.ID + " already added, skipping adding it ...");
                    continue;
                }

                userGroupPermissions.Add(groupPerms);
            }

            return userGroupPermissions;
        }

        private Dictionary<int, GroupPermissions> GetGroupPermissions(List<MGGroup> userGroups)
        {
            throw new NotImplementedException();
        }

        public List<MGGroup> GetUserGroups(MGUser user)
        {
            bool isFilterOutSuperGroup = false;

            return GetUserGroups(user, isFilterOutSuperGroup);
        }

        public List<MGGroup> GetUserGroups(MGUser user, bool isFilterOutSuperGroup)
        {
            if (user == null)
            {
                Logger.LogError(5, "Cannot GetUserGroups for NULL user!");
                return null;
            }
            else if (user.ID < 1)
            {
                Logger.LogError(5, "Cannot GetUserGroups for invalid user.ID (" + user.ID + ")!");
                return null;
            }

            List<MGGroup> userGroups = null;

            UserOperations userHelper = null;
            GroupOperations groupHelper = null;
            try
            {
                userHelper = new UserOperations(Lcf);

                List<int> userGroupIDs = userHelper.GetUserGroupsIDs(user.ID);
                if (userGroupIDs == null)
                {
                    Logger.LogError(5, "Cannot GetUserGroups as retrieved NULL list of userGroupIDs for user.ID (" + user.ID + ")!");
                    return null;
                }

                userGroups = new List<MGGroup>(userGroupIDs.Count);

                groupHelper = new GroupOperations(Lcf);
                MGGroup group;
                foreach (int groupID in userGroupIDs)
                {
                    if (groupID < 1)
                    {
                        Logger.LogError(5, "Invalid groupID detected, skipping it ...");
                        continue;
                    }

                    group = groupHelper.GetGroup(groupID);
                    if (group == null)
                    {
                        Logger.LogError(5, "NULL MGGroup detected, skipping it ...");
                        continue;
                    }

                    if(isFilterOutSuperGroup)
                    {
                        if (group.Name != null && group.Name.Equals(GroupAdministration.SUPER_USER_GROUP_NAME, StringComparison.CurrentCultureIgnoreCase))
                        {
                            continue;
                        }
                    }

                    userGroups.Add(group);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Failure getting UserGroups for user.ID (" + user.ID + ") at " + ex.StackTrace);
                return null;
            }
            finally
            {
                if (userHelper != null)
                    userHelper.Finish();
                if (groupHelper != null)
                    groupHelper.Finish();
            }

            return userGroups;
        }

        #endregion

    }

}
