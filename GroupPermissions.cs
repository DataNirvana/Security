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
    /// This class encapsultes the permissions a UserGroup has to access Content, Functionality & Display Modes.
    /// </summary>
    public class GroupPermissions
    {

        #region InnerClasses

        public class GroupContentPermission
        {

            private SecureRequestContext.ContentType contentType = SecureRequestContext.ContentType.UNKNOWN;
            /// <summary>
            /// The type of content that is permitted through this entry e.g. a report or stat layer.
            /// </summary>
            public SecureRequestContext.ContentType ContentType
            {
                get
                {
                    return contentType;
                }
                set
                {
                    contentType = value;
                }
            }

            private int contentID = -1;
            /// <summary>
            /// The unique ID of the the content permitted through this entry e.g. a report ID or stat layer DLL_ID.
            /// </summary>
            public int ContentID
            {
                get
                {
                    return contentID;
                }
                set
                {
                    contentID = value;
                }
            }

        }

        public class GroupFunctionalityPermission
        {

            private SecureRequestContext.FunctionalityType functionType = SecureRequestContext.FunctionalityType.UNKNOWN;
            /// <summary>
            /// The type of functionality that is permitted through this entry e.g. 'SUG Admin' or 'What Info'.
            /// </summary>
            public SecureRequestContext.FunctionalityType FunctionType
            {
                get
                {
                    return functionType;
                }
                set
                {
                    functionType = value;
                }
            }

            private int functionalityID = -1;
            /// <summary>
            /// The unique ID of the the functionality permitted through this entry.
            /// </summary>
            public int FunctionalityID
            {
                get
                {
                    return functionalityID;
                }
                set
                {
                    functionalityID = value;
                }
            }

            private string description = null;
            /// <summary>
            /// The display description of the the functionality permitted through this entry.
            /// </summary>
            public string Description
            {
                get
                {
                    return description;
                }
                set
                {
                    description = value;
                }
            }

        }

        public class GroupDisplayPermission
        {

            private SecureRequestContext.DisplayType displayType = SecureRequestContext.DisplayType.UNKNOWN;
            /// <summary>
            /// The type of display that is permitted through this entry e.g. 'map' or 'table'.
            /// </summary>
            public SecureRequestContext.DisplayType DisplayType
            {
                get
                {
                    return displayType;
                }
                set
                {
                    displayType = value;
                }
            }

            private int displayID = -1;
            /// <summary>
            /// The unique ID of the the display permission permitted through this entry.
            /// </summary>
            public int DisplayID
            {
                get
                {
                    return displayID;
                }
                set
                {
                    displayID = value;
                }
            }
            private string description = null;
            /// <summary>
            /// The display description of the the display permitted through this entry.
            /// </summary>
            public string Description
            {
                get
                {
                    return description;
                }
                set
                {
                    description = value;
                }
            }

        }

        #endregion

        #region Properties

        private long groupID = -1;
        /// <summary>
        /// The unique ID of the Group from the ID column in the groups table.
        /// </summary>
        public long GroupID
        {
            get
            {
                return groupID;
            }
            set
            {
                groupID = value;
            }
        }

        private List<GroupContentPermission> groupContentPermissions = null;
        /// <summary>
        /// The content permissions associated with this group only (through the xrefs).
        /// </summary>
        public List<GroupContentPermission> GroupContentPermissions
        {
            get
            {
                return groupContentPermissions;
            }
            set
            {
                groupContentPermissions = value;
            }
        }

        private List<GroupFunctionalityPermission> groupFunctionPermissions = null;
        /// <summary>
        /// The functionality permissions associated with this group only (through the xrefs).
        /// </summary>
        public List<GroupFunctionalityPermission> GroupFunctionPermissions
        {
            get
            {
                return groupFunctionPermissions;
            }
            set
            {
                groupFunctionPermissions = value;
            }
        }

        private List<GroupDisplayPermission> groupDisplayPermissions = null;
        /// <summary>
        /// The functionality permissions associated with this group only (through the xrefs).
        /// </summary>
        public List<GroupDisplayPermission> GroupDisplayPermissions
        {
            get
            {
                return groupDisplayPermissions;
            }
            set
            {
                groupDisplayPermissions = value;
            }
        }



        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new empty GroupPermissions object.
        /// It will have no permissions initially.
        /// </summary>
        public GroupPermissions()
        {
            // NOP.
        }

        /// <summary>
        /// Creates a new GroupPermissions object with the given group ID.
        /// It will have no permissions initially.
        /// </summary>
        public GroupPermissions(int groupID)
        {
            this.GroupID = groupID;
        }

        #endregion

        #region Public Methods

        public List<GroupContentPermission> GetGroupContentPermissions(List<MGSecurityTag> groupContentSecKeyValPairs)
        {
            if (groupContentSecKeyValPairs == null)
            {
                Logger.LogError(5, "Cannot GetGroupContentPermissions from NULL list of SecurityTags!");
                return null;
            }
            List<GroupContentPermission> groupContentPerms = null;

            try
            {
                groupContentPerms = new List<GroupContentPermission>();
                GroupContentPermission groupContentPerm = null;

                SecureRequestContext.ContentType contentType = SecureRequestContext.ContentType.UNKNOWN;

                int contentID = -1;
                foreach (MGSecurityTag securityTag in groupContentSecKeyValPairs)
                {
                    contentType = SecureRequestContext.ContentType.UNKNOWN;
                    contentID = -1;

                    if (securityTag.Name == null || securityTag.Name == String.Empty)
                    {
                        Logger.LogWarning("NULL security tag name detected, skipping it ...");
                        continue;
                    }
                    try
                    {
                        contentType = (SecureRequestContext.ContentType)
                            Enum.Parse(typeof(SecureRequestContext.ContentType), securityTag.Name.ToUpper());
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(5, "Problem parsing security tag " + securityTag.Name.ToUpper() + " at " + ex.StackTrace);
                        return null;
                    }

                    if (contentType != SecureRequestContext.ContentType.UNKNOWN)
                    {
                        groupContentPerm = new GroupContentPermission();
                        groupContentPerm.ContentType = contentType;

                        if (securityTag.SubType > 0)
                            contentID = securityTag.SubType;

                        groupContentPerm.ContentID = contentID;

                        groupContentPerms.Add(groupContentPerm);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting groupContentPermissions at " + ex.StackTrace);
                return null;
            }
            return groupContentPerms;
        }

        public List<GroupDisplayPermission> GetGroupDisplayPermissions(List<MGSecurityTag> groupDisplaySecKeyValPairs)
        {
            if (groupDisplaySecKeyValPairs == null)
            {
                Logger.LogError(5, "Cannot GetGroupDisplayPermissions from NULL list of SecurityTags!");
                return null;
            }

            List<GroupDisplayPermission> groupDisplayPerms = null;
            GroupDisplayPermission groupDisplay = null;

            try
            {
                groupDisplayPerms = new List<GroupDisplayPermission>();
                SecureRequestContext.DisplayType displayType;

                foreach (MGSecurityTag securityTag in groupDisplaySecKeyValPairs)
                {
                    displayType = SecureRequestContext.DisplayType.UNKNOWN;

                    if (securityTag.Name == null || securityTag.Name == String.Empty)
                    {
                        Logger.LogWarning("NULL security tag name detected, skipping it ...");
                        continue;
                    }
                    try
                    {
                        displayType = (SecureRequestContext.DisplayType)
                            Enum.Parse(typeof(SecureRequestContext.DisplayType), securityTag.Name.ToUpper());
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(5, "Problem parsing security tag " + securityTag.Name.ToUpper() + " at " + ex.StackTrace);
                        return null;
                    }

                    if (displayType != SecureRequestContext.DisplayType.UNKNOWN)
                    {
                        groupDisplay = new GroupDisplayPermission();
                        groupDisplay.DisplayType = displayType;
                        groupDisplay.DisplayID = securityTag.ID;
                        groupDisplay.Description = securityTag.Description;
                        groupDisplayPerms.Add(groupDisplay);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting GetGroupDisplayPermissions at " + ex.StackTrace);
                return null;
            }
            return groupDisplayPerms;
        }

        public List<GroupFunctionalityPermission> GetGroupFunctionPermissions(List<MGSecurityTag> groupFunctionSecKeyValPairs)
        {
            if (groupFunctionSecKeyValPairs == null)
            {
                Logger.LogError(5, "Cannot GetGroupFunctionPermissions from NULL list of SecurityTags!");
                return null;
            }

            List<GroupFunctionalityPermission> groupFunctionPerms = null;
            GroupFunctionalityPermission groupFunction = null;
            try
            {
                groupFunctionPerms = new List<GroupFunctionalityPermission>();

                SecureRequestContext.FunctionalityType functionType;
                foreach (MGSecurityTag securityTag in groupFunctionSecKeyValPairs)
                {
                    functionType = SecureRequestContext.FunctionalityType.UNKNOWN;

                    if (securityTag.Name == null || securityTag.Name == String.Empty)
                    {
                        Logger.LogWarning("NULL security tag name detected, skipping it ...");
                        continue;
                    }
                    try
                    {
                        functionType = (SecureRequestContext.FunctionalityType)
                            Enum.Parse(typeof(SecureRequestContext.FunctionalityType), securityTag.Name.ToUpper());
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(5, "Problem parsing security tag " + securityTag.Name.ToUpper() + " at " + ex.StackTrace);
                        return null;
                    }

                    if (functionType != SecureRequestContext.FunctionalityType.UNKNOWN)
                    {
                        groupFunction = new GroupFunctionalityPermission();
                        groupFunction.FunctionType = functionType;
                        groupFunction.FunctionalityID = securityTag.ID;
                        groupFunction.Description = securityTag.Description;
                        groupFunctionPerms.Add(groupFunction);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(5, "Error getting GroupFuncionalityPermissions at " + ex.StackTrace);
                return null;
            }
            return groupFunctionPerms;
        }

        #endregion

    }

}
